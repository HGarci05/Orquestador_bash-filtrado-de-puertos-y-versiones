

# 1. Variables Globales
TARGET="$1"
NMAP_OUTPUT="nmap_scan_raw.txt"
REPORT_OUTPUT="vulnerability_report_${TARGET//[^a-zA-Z0-9]/_}.md"
SHODAN_API_KEY="${SHODAN_API_KEY}"

# Variables de metadatos
DATE_TIME=$(date "+%Y-%m-%d %H:%M:%S")
USER_RUN=$(whoami)

declare -a RECOMMENDATIONS=()

# 2. Helpers y Funciones de Reporte

# Función para imprimir mensajes de estado (a stderr)
function status_message {
    local TYPE="$1"
    local MESSAGE="$2"
    echo "$TYPE $MESSAGE" >&2
}

# Función para imprimir en CONSOLA y guardar en ARCHIVO simultáneamente
function md_out {
    local content="$1"
    echo "$content" | tee -a "$REPORT_OUTPUT"
}

# Función para añadir una recomendación al array
function add_recommendation {
    local RECOMMENDATION="$1"
    RECOMMENDATIONS+=("$RECOMMENDATION")
}

# Función de limpieza y finalización
function cleanup_and_finish {
    md_out "---"
    md_out "## 3. Conclusión y Plan de Acción Defensivo"
    
    # Añadir recomendaciones consolidadas y categorizadas
    if [ ${#RECOMMENDATIONS[@]} -gt 0 ]; then
        md_out "### Prioridades de Mitigación (Acciones Requeridas):"
        
        md_out "#### Críticas y Urgentes (Parcheo Inmediato)"
        md_out "* Auditar y mitigar todos los servicios que mostraron coincidencias en **Shodan (CVEs)** o **Exploit-DB**."
        
        md_out "#### Mejora Continua (Hardening y Actualización)"
        # Eliminar duplicados antes de imprimir
        printf "%s\n" "${RECOMMENDATIONS[@]}" | awk '!seen[$0]++' | while read -r rec; do
            md_out "* $rec"
        done
        md_out "\n* **Política de Parcheo:** Implementar un proceso estricto de gestión de parches para mantener todos los servicios en la última versión estable y segura."
        md_out ""
    fi
    
    status_message "[OK]" "Análisis finalizado."
    md_out "* **ESTADO:** Informe completo generado y guardado en: **$REPORT_OUTPUT**"

    # Limpieza de archivo temporal
    rm -f "$NMAP_OUTPUT" >&2
    status_message "[FIN]" "Limpieza de archivos temporales completada."
}

# 3. Funciones de Configuración y Escaneo


# Función para validar la entrada y los requisitos del entorno
function validate_environment {
    if [ -z "$TARGET" ]; then
        status_message "[ERROR]" "Uso: $0 <Dirección_IP_o_Dominio>"
        exit 1
    fi

    # Comprueba dependencias
    local missing=()
    for cmd in nmap searchsploit curl jq; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done
    if [ ${#missing[@]} -ne 0 ]; then
        status_message "[ERROR]" "Faltan dependencias: ${missing[*]}. Instálalas antes de continuar."
        exit 1
    fi

    # Inicializar el informe (escribir encabezado con metadatos)
    > "$REPORT_OUTPUT"
    md_out "# Informe de Análisis de Vulnerabilidades: $TARGET"
    md_out "\n* **Fecha y Hora del Análisis:** $DATE_TIME"
    md_out "* **Analista:** $USER_RUN"
    md_out "* **Objetivo (Target):** $TARGET"
    if [ -z "$SHODAN_API_KEY" ]; then
        md_out "* **Shodan API:** Inactiva (Clave no configurada)."
        status_message "[ADVERTENCIA]" "La clave de API de Shodan no está configurada. La sección de CVEs será omitida."
    else
        md_out "* **Shodan API:** Activa."
    fi
    md_out "\n---"
    status_message "[INICIO]" "Iniciando orquestador para $TARGET. Informe en pantalla y archivo."
    md_out ""
}

# Función para ejecutar Nmap y guardar la salida
function run_nmap_scan {
    status_message "[INICIO]" "Ejecutando Nmap para escaneo de servicios..."
    md_out "## 1. Escaneo de Servicios y Versiones (Nmap)"
    
    nmap -sV -A "$TARGET" -oN "$NMAP_OUTPUT" &> /dev/null
    NMAP_STATUS=$?

    if [ $NMAP_STATUS -ne 0 ]; then
        status_message "[ERROR]" "Error al ejecutar Nmap ($NMAP_STATUS). Revisar permisos o conectividad."
        md_out "\n* **ESTADO:** Fallido. El análisis no pudo continuar."
        exit 1
    fi
    
    status_message "[OK]" "Escaneo de Nmap completado."
    
    md_out "\n**Comando Ejecutado:** \`nmap -sV -A $TARGET\`"
    md_out "* **Estado:** Completado. Detalle raw en \`$NMAP_OUTPUT\`."
    
    md_out "\n### Puertos y Servicios Abiertos Identificados"
    md_out "| Puerto/Protocolo | Estado | Servicio (Versión) |"
    md_out "| :--- | :--- | :--- |"
    
    # Crear la tabla de servicios abiertos para el informe
    grep -E '^[0-9]+/tcp.*open' "$NMAP_OUTPUT" | while read -r LINE; do
        local PORT_STATE=$(echo "$LINE" | awk '{print $1 "/" $2}') # Ej: 80/tcp open
        local SERVICE_DETAIL=$(echo "$LINE" | awk '{$1=$2=""; print $0}' | xargs)
        local PORT=$(echo "$LINE" | awk '{print $1}' | cut -d/ -f1) # Necesario para el parsing posterior
        md_out "| $PORT | open | $SERVICE_DETAIL |"
    done
    md_out "\n---"
}

# 4. Funciones de Análisis


# Función para buscar exploits con Searchsploit
function run_searchsploit {
    local SERVICE="$1"
    local VERSION="$2"

    md_out "#### A. Referencias Locales (Searchsploit)"
    
    SEARCH_RESULT=$(searchsploit --nocolor "$SERVICE" "$VERSION" 2>&1)
    
    if echo "$SEARCH_RESULT" | grep -q "No se encontraron resultados"; then
        md_out "* **Estado:** No se encontraron coincidencias directas para \`$SERVICE $VERSION\`."
        add_recommendation "Aplicar la última versión o parche de seguridad disponible para el servicio **$SERVICE** (versión $VERSION)."
    else
        md_out "* **Estado:** Coincidencias de exploits en la base de datos local encontradas."
        md_out "\n##### Detalles de Coincidencias (Exploit-DB)"
        md_out "\`\`\`text"
        # Imprimir solo las líneas de resultados
        echo "$SEARCH_RESULT" | head -n -1 | tee -a "$REPORT_OUTPUT"
        md_out "\`\`\`"
        
        # Añadir recomendación de revisión
        add_recommendation "Investigar las referencias encontradas para el servicio **$SERVICE $VERSION** y aplicar parches inmediatamente."
        
        # Generar la lista de exploits sugeridos (Rutas)
        md_out "\n##### Rutas Sugeridas para Pruebas (Exploit-DB):"
        echo "$SEARCH_RESULT" | grep -E '^ |[0-9]{4,}' | awk '{print $NF}' | grep -E '^[0-9]+(\.py|\.sh|\.txt|\.rb|\.pl)?$' | while read -r EXPLOIT_ID; do
            EXPLOIT_PATH=$(searchsploit -p "$EXPLOIT_ID" | grep -E 'Exploit:\s*')
            md_out "* **ID $EXPLOIT_ID:** ${EXPLOIT_PATH}"
        done
    fi
}

# Función para consultar la API de Shodan
function query_shodan_api {
    local IP="$1"
    local PORT="$2"
    
    md_out "#### B. CVEs en Fuentes Abiertas (Shodan API)"
    
    if [ -z "$SHODAN_API_KEY" ]; then
        md_out "* **Estado:** Omisión. La clave de API de Shodan no está configurada."
        return
    fi

    local SHODAN_URL="https://api.shodan.io/shodan/host/$IP?key=$SHODAN_API_KEY&history=false&minified=true"
    local SHODAN_DATA=$(curl -s "$SHODAN_URL")
    
    local CVE_LIST=$(echo "$SHODAN_DATA" | jq -r ".data[] | select(.port == $PORT) | .vulns[]" 2>/dev/null)
    
    if [ -z "$CVE_LIST" ]; then
        md_out "* **Shodan:** No se encontraron CVEs o información adicional para este servicio."
    else
        md_out "* **Shodan:** **Vulnerabilidades CVEs reportadas encontradas.**"
        md_out "##### Identificadores de CVEs:"
        # Lista los CVEs separados por '*' con una nota de prioridad
        echo "$CVE_LIST" | while read -r cve; do
            md_out "* **$cve** - Prioridad: **ALTA** (Se requiere revisión inmediata)."
        done
        
        add_recommendation "Se encontraron CVEs reportados por Shodan para el servicio en el Puerto $PORT. Estos deben ser priorizados para parcheo inmediato."
    fi
}

# Función principal que orquesta el parsing y el análisis por servicio
function analyze_services {
    md_out "## 2. Análisis Detallado por Servicio"
    md_out ""

    # Iterar sobre las líneas de servicios abiertos de Nmap
    grep -E '^[0-9]+/tcp.*open' "$NMAP_OUTPUT" | while read -r LINE; do
        
        # --- Parsing de Datos ---
        local PORT=$(echo "$LINE" | awk '{print $1}' | cut -d/ -f1)
        local SERVICE=$(echo "$LINE" | awk '{print $3}')
        local VERSION_FULL=$(echo "$LINE" | awk '{$1=$2=$3=""; print $0}' | xargs)
        local VERSION=$(echo "$VERSION_FULL" | awk '{print $1}')

        if [ -z "$SERVICE" ] || [ "$SERVICE" = "unknown" ]; then
            continue
        fi
        
        status_message "[BUSCANDO]" "Analizando Puerto $PORT: $SERVICE $VERSION_FULL"
        
        # --- Estructura del Informe ---
        md_out "---"
        md_out "### Puerto $PORT: $SERVICE | Versión: $VERSION_FULL"
        md_out ""
        
        # Ejecutar funciones de análisis
        run_searchsploit "$SERVICE" "$VERSION"
        query_shodan_api "$TARGET" "$PORT"
        
    done
}

# 5. Función MAIN 

function main {
    # 0. Validar Entorno
    validate_environment

    # 1. Ejecutar Escaneo Nmap
    run_nmap_scan

    # 2. Analizar Servicios Descubiertos (Iteración y Parsing)
    analyze_services

    # 3. Limpieza y Fin
    cleanup_and_finish
}

# Ejecutar la función principal al final del script
main

