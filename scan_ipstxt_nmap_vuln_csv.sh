#!/bin/bash

input_file="ips.txt"
output_dir="nmap_results"
csv_file="nmap_summary.csv"

mkdir -p "$output_dir"

# Crear el archivo CSV con encabezados
echo "IP,Puerto,Servicio,Versión,Vulnerabilidad" > "$csv_file"

while IFS= read -r ip; do
  # Limpiar espacios y saltos de línea
  ip=$(echo "$ip" | tr -d '[:space:]')

  # Saltar líneas vacías
  if [ -z "$ip" ]; then
    continue
  fi

  echo "Escaneando $ip..."

  temp_gnmap="${output_dir}/${ip}_scan.gnmap"
  temp_nmap="${output_dir}/${ip}_scan.txt"

  # Escaneo con evasión básica y scripts de vulnerabilidades
  nmap -sS -f -sV -O --script=vuln -oN "$temp_nmap" -oG "$temp_gnmap" "$ip"

  echo "Escaneo de $ip completado. Resultados guardados en $temp_nmap"

  # Extraer puertos abiertos y servicios desde archivo .gnmap
  ports_line=$(grep "^Host: $ip" "$temp_gnmap" | grep "Ports:")

  IFS=',' read -ra ports <<< "$(echo "$ports_line" | sed -n 's/.*Ports: //p')"

  for port_info in "${ports[@]}"; do
    IFS='/' read -ra fields <<< "$port_info"
    port="${fields[0]}"
    state="${fields[1]}"
    proto="${fields[2]}"
    service="${fields[4]}"

    if [ "$state" == "open" ]; then
      version_line=$(grep -A 1 "^$port/tcp open" "$temp_nmap" | tail -n 1)
      version=$(echo "$version_line" | sed 's/^[[:space:]]*//')

      vuln=$(grep -A 3 -i "VULNERABLE" "$temp_nmap" | grep -i "$port/tcp" | head -n 1 | sed 's/^[[:space:]]*//')

      if [ -z "$vuln" ]; then
        vuln="No detectada"
      else
        vuln=$(echo "$vuln" | tr '\n' ' ' | cut -c1-100)
      fi

      echo "\"$ip\",\"$port\",\"$service\",\"$version\",\"$vuln\"" >> "$csv_file"
    fi
  done

done < "$input_file"

echo "Resumen guardado en $csv_file"

# Elaborado por Alex Cabello Leiva - AlexCocoPro

echo "Script elaborado por Alex Cabello Leiva - AlexCocoPro"

echo "Resumen guardado en $csv_file"
