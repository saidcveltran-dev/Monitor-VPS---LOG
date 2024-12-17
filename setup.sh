#!/bin/bash

# Script de instalación de Monitor VPS

set -e

# Comprobación de permisos root
if [[ $EUID -ne 0 ]]; then
   echo "Este script debe ejecutarse con privilegios de root (sudo)" 
   exit 1
fi

# Configuración
INSTALL_DIR="/opt/nginx-log-monitor"
CONFIG_DIR="/etc/nginx-monitor"
LOG_DIR="/var/log/nginx-monitor"

# Creación de los directorios necesarios
mkdir -p $INSTALL_DIR
mkdir -p $CONFIG_DIR
mkdir -p $LOG_DIR

# Instalación Python y pip si no están ya instalados
apt-get update
apt-get install -y python3 python3-pip python3-venv

# Creación de un entorno virtual Python
python3 -m venv $INSTALL_DIR/venv
source $INSTALL_DIR/venv/bin/activate

# Requisitos de instalación
pip install -r requirements.txt

# Copia de archivos de script
cp nginx_log_monitor.py $INSTALL_DIR/
cp requirements.txt $INSTALL_DIR/

# Copia de ejemplo de configuración
cp config.yaml $CONFIG_DIR/config.yaml

# Creación del servicio en systemd
cat << EOF > /etc/systemd/system/nginx-log-monitor.service
[Unit]
Description=Nginx Log Monitor
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/nginx_log_monitor.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# Recargando systemd, habilitando e iniciando el servicio
systemctl daemon-reload
systemctl enable nginx-log-monitor.service
systemctl start nginx-log-monitor.service

echo "Instalación completada. El monitor de logs de Nginx está funcionando."
echo "Puede configurarlo en $CONFIG_DIR/config.yaml"