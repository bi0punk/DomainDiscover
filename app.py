from scapy.all import sniff, DNS, DNSQR
import socket

# Lista de dominios a monitorear
dominios_interes = ["instagram.com", "facebook.com"]

# Función para capturar paquetes DNS y filtrar dominios de interés
def detectar_acceso(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qd is not None:
        try:
            # Obtener el nombre de dominio que se está consultando
            dominio_consultado = packet[DNSQR].qname.decode('utf-8').strip('.')
            ip_dispositivo = packet[IP].src  # IP del dispositivo que realizó la consulta

            # Verificar si el dominio es de interés
            for dominio in dominios_interes:
                if dominio_consultado.endswith(dominio):
                    print(f"¡Alerta! El dispositivo {ip_dispositivo} accedió a {dominio_consultado}")
                    break
        except Exception as e:
            print(f"Error: {e}")

# Captura de paquetes en la red local (puedes ajustar la interfaz de red si es necesario)
print("Iniciando la captura de paquetes en la red local...")
sniff(filter="udp port 53", prn=detectar_acceso, store=0)
