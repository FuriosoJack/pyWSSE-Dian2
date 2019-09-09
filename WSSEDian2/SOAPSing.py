import hashlib
import uuid
from string import Template
import base64
from wssedian2.Utils import find_node
from wssedian2.SingNS import *
from lxml import etree
import datetime
from pytz import timezone

try:
    from StringIO import StringIO
except ImportError:
    from io import BytesIO as StringIO

envelope_template = Template('''<${soap}:Envelope xmlns:${soap}="${soap_url}" xmlns:${wcf_env}="${wcf_env_url}">
<${soap}:Header xmlns:${wsa_env}="${wsa_env_url}">
            <${wsse}:Security xmlns:${wsse}="${wsse_url}" xmlns:${wsu}="${wsu_url}">
                <wsu:Timestamp wsu:Id="${timestam_id}">
                <wsu:Created>${timestamp_created}</wsu:Created>
                <wsu:Expires>${timestamp_expires}</wsu:Expires>
                </wsu:Timestamp>
               <${wsse}:BinarySecurityToken EncodingType="${encoding_base64_url}" ValueType="${value_x509_url}" ${wsu}:Id="${cert_id}">${sec_token}</${wsse}:BinarySecurityToken>
               <${ds}:Signature xmlns:${ds}="${ds_url}" Id="${sig_id}">
                  <${ds}:SignedInfo>
                     <${ds}:CanonicalizationMethod Algorithm="${ec_url}">
                        <${ec}:InclusiveNamespaces xmlns:${ec}="${ec_url}" PrefixList="${soap} ${wsa_env} ${wcf_env}"/>
                     </${ds}:CanonicalizationMethod>
                     <${ds}:SignatureMethod Algorithm="${algo_sha256}"/>
                     <${ds}:Reference URI="#${body_id}">
                        <${ds}:Transforms>
                           <${ds}:Transform Algorithm="${ec_url}">
                              <${ec}:InclusiveNamespaces xmlns:${ec}="${ec_url}" PrefixList="${soap} ${wcf_env}"/>
                           </${ds}:Transform>
                        </${ds}:Transforms>
                        <${ds}:DigestMethod Algorithm="${algo_digest_sha256}"/>
                        <${ds}:DigestValue></${ds}:DigestValue>
                     </${ds}:Reference>
                  </${ds}:SignedInfo>
                  <${ds}:SignatureValue></${ds}:SignatureValue>
                  <${ds}:KeyInfo Id="${key_id}">
                     <${wsse}:SecurityTokenReference ${wsu}:Id="${sec_token_id}">
                        <${wsse}:Reference URI="#${cert_id}" ValueType="${value_x509_url}"/>
                     </${wsse}:SecurityTokenReference>
                  </${ds}:KeyInfo>
               </${ds}:Signature>
            </${wsse}:Security>
            <${wsa_env}:Action>http://wcf.dian.colombia/IWcfDianCustomerServices/GetStatusZip</${wsa_env}:Action>
            <${wsa_env}:To wsu:Id="${body_id}" xmlns:${wsu}="${wsu_url}" xmlns:${soap}="${soap_url}">https://vpfe-hab.dian.gov.co/WcfDianCustomerServices.svc?wsdl</${wsa_env}:To>
         </${soap}:Header>
         <${soap}:Body></${soap}:Body>
</${soap}:Envelope>''')

namespaces_dict = {
    'soap': NS_SOAP,
    'soap_url': NS_SOAP_URL,
    'soap_env': NS_SOAP_ENV,
    'soap_env_url': NS_SOAP_ENV_URL,
    'wsse': NS_WSSE,
    'wsse_url': NS_WSSE_URL,
    'wsu': NS_WSU,
    'wsu_url': NS_WSU_URL,
    'wcf_env': NS_WCF,
    'wcf_env_url': NS_WCF_URL,
    'ds': NS_DS,
    'ds_url': NS_DS_URL,
    'ec': NS_EC,
    'ec_url': NS_EC_URL,
    'eet_url': NS_EET_URL,
    'wsa_env': NS_WSA,
    'wsa_env_url': NS_WSA_URL,
    'eet_url': NS_EET_URL,
    'algo_sha256': ALGORITHM_SHA256,
    'algo_digest_sha256': ALGORITHM_DIGEST_SHA256,
    'value_x509_url': VALUE_X509_URL,
    'encoding_base64_url': ENCODING_BASE64_URL

}
class SOAPSing(object):
    

    def __init__(self,signing):
        
        self.signing = signing
    
    
    def get_normalized_subtree(self,node, includive_prefixes=[]):
        tree = etree.ElementTree(node)
        ss = StringIO()
        tree.write_c14n(
            ss, exclusive=True, inclusive_ns_prefixes=includive_prefixes)
        return ss.getvalue()
        
    def calculate_node_digest(self,node):
        data = self.get_normalized_subtree(node, ['soap','wcf','wsa','wsu'])
        return hashlib.sha256(data).digest()
        
  
    """
    def canonicalize(self, xml, c14n_exc=True):
        output = BytesIO()
        et = ET.parse(BytesIO(xml))
        et.write_c14n(output, exclusive=c14n_exc)
       
        return output.getvalue()
    
    def sha256_hash_digest(self,payload):
        "Create a SHA1 hash and return the base64 string"
        return base64.b64encode(hashlib.sha256(payload).digest())
       
        
    def loadXML(self):
        elementSecurity = ET.Element("{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}wss:Security")
        self.domDocument.append(elementSecurity)
    """    
    
    def sing(self,nodeSing):
        
         # Prepare parser
        parser = etree.XMLParser(remove_blank_text=True, ns_clean=False)
        
        # Prepare IDs for header
        body_id = 'ID-'+uuid.uuid4().hex
        cert_id = 'X509-'+uuid.uuid4().hex
        sig_id = 'SIG-' + uuid.uuid4().hex
        key_id = 'KI-'+ uuid.uuid4().hex
        sec_token_id='STR-'+ uuid.uuid4().hex
        timestam_id = 'TS-' +uuid.uuid4().hex
        
        
        now =  datetime.datetime.utcnow() # current date and time
        nowExpire = now + datetime.timedelta(seconds=60000)
        values = dict(namespaces_dict)
        values.update({
            'body_id': body_id,
            'timestam_id': timestam_id,
            'cert_id': cert_id,
            'sig_id': sig_id,
            'key_id':key_id,
            'timestamp_created': now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            'timestamp_expires': nowExpire.strftime("%Y-%m-%dT%H:%M:%SZ"),
            'sec_token_id': sec_token_id,
            'sec_token': base64.b64encode(self.signing.get_cert_binary()).decode('utf8')})
            
         # Create SOAP envelope
        envelope = etree.XML(envelope_template.substitute(values), parser=parser)
        
        
        
        # Find soap:Body
        body = find_node(envelope, 'Body', NS_SOAP_URL)
        # Fill in Trzby into soap:Body
        body.append(nodeSing)
        
        
        #Find wsa:to
        to = find_node(envelope, 'To', NS_WSA_URL)
        
        # Calculate digest of soap:Body
        body_digest = self.calculate_node_digest(to)
         # Find ds:DigestValue and store the computed digest
        digest_node = find_node(envelope, 'DigestValue', NS_DS_URL)
        
        
        digest_node.text = base64.b64encode(body_digest)
        
        # Find ds:SignedInfo node and get normalized text of it
        signature_node = find_node(envelope, 'SignedInfo', NS_DS_URL)
        normalized_signing = self.get_normalized_subtree(signature_node, ['soap','wcf','wsa'])
       
        # FInd ds:SignatureValue and store there signature of ds:SignedInfo
        signature_value_node = find_node(envelope, 'SignatureValue', NS_DS_URL)
        signature_value_node.text = base64.b64encode(self.signing.sign_text(normalized_signing, 'sha256'))
        
        return envelope
   
