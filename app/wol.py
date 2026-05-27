from wakeonlan import send_magic_packet

def wake_device(mac_address):
    """Send a Wake-on-LAN magic packet to the given MAC address."""
    try:
        send_magic_packet(mac_address)
        return True
    except Exception as e:
        print(f"Error sending WoL to {mac_address}: {e}")
        return False
