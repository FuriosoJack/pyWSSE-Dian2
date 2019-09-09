# pyWSSE-Dian2
Generacion de la peticion soap firmada para hacer las peticiones al servidor de facturacion electronica de la dian en colombia v2 con prevalidacion

## Ejemplo

```python
from wssedian2.SOAPSing import SOAPSing
from wssedian2.Signing import Signing
import lxml.etree as ET

stringRequest = """<wcf:GetStatusZip><wcf:trackId>xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx</wcf:trackId></wcf:GetStatusZip>""""
pathCert = "certificado.p12"
passwordCert = "contraseña"
singing = Signing(pathCert,passwordCert)    
element = ET.fromstring(stringRequest)
singner = SOAPSing(singing)
#Se devuelve un elemento etree
soapSinged = singner.sing(element)
# Asi que se tranforma a string para comodidad
soapSingedStrin = ET.tostring(soapSinged)
```