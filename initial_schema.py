def begin_Handshake():
    pass

def begin_Diffie_Hellman():
    pass

def finalize_Diffie_Hellman():
    pass

def begin_Crypto_Check():
    pass

def finalize_Crypto_Check():
    pass

def finalize_Handshake():
    pass

def handle_Heartbeat():
    pass

def begin_Client_Termination():
    pass

def Terminate_Client():
    pass

def finalize_Client_Termination():
    pass

def force_Terminate_Connection():
    pass

{
    CHI: begin_Handshake,
    SDH: begin_Diffie_Hellman,
    CDH: finalize_Diffie_Hellman,
    SCC: begin_Crypto_Check,
    CCC: finalize_Crypto_Check,
    SHF: finalize_Handshake,
    CHB: handle_Heartbeat,
    CGB: begin_Client_Termination,
    SGB: Terminate_Client,
    CFL: finalize_Client_Termination,
    SFL: force_Terminate_Connection
}