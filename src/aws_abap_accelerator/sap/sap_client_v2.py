

from typing import Optional, List, Dict, Any, Tuple
import logging
from urllib.parse import urljoin, quote

from sap.sap_client import SAPADTClient
from sap_types.sap_types import (
    SAPConnection, ADTObject, ATCResult, UnitTestResult, CreateObjectRequest,
    SyntaxCheckResult, ActivationResult, ObjectOperationResult, ATCCheckArgs,
    SyntaxError as SAPSyntaxError, SyntaxWarning, PackageInfo, TransportRequest, CreatePackageRequest,
    CreateTransportRequest, PackageOperationResult, TransportOperationResult,
    EnhancementInfo, CreateEnhancementRequest, EnhancementSpotInfo, BadiDefinitionInfo,
    EnhancementOperationResult, EnhancementType, InterfaceInfo, FunctionGroupInfo,
    FunctionModuleInfo, FunctionGroupIncludeInfo, CreateInterfaceRequest,
    CreateFunctionGroupRequest, CreateFunctionModuleRequest, InterfaceOperationResult,
    FunctionOperationResult, DataElementInfo, DomainInfo, TableInfo, StructureInfo,
    TableTypeInfo, SearchHelpInfo, ViewInfo, LockObjectInfo, CreateDataElementRequest,
    CreateDomainRequest, CreateTableRequest, CreateStructureRequest, CreateTableTypeRequest,
    CreateSearchHelpRequest, CreateViewRequest, CreateLockObjectRequest, DDICOperationResult,
    SeverityType, ObjectType, ADTAPICallResponse, ADTCreateRequest
)
from utils.logger import rap_logger
from utils.security import (
    sanitize_for_logging, sanitize_for_xml, validate_numeric_input,
    decrypt_from_memory, validate_sap_host, sanitize_file_path
)

logger = logging.getLogger(__name__)

class SAPADTClient2:

  def __init__(self, connection: SAPConnection, v1_client: SAPADTClient):
      self.v1_client = v1_client  # Keep reference to old client for compatibility
      # self.connection = connection
      # self.session_id: Optional[str] = None
      # self.csrf_token: Optional[str] = None
      # self.cookies: Dict[str, str] = {}
      # self.session: Optional[aiohttp.ClientSession] = None
      # self.keychain_identifier: Optional[str] = None  # Store keychain identifier for dynamic system ID
      
      # # Validate SAP host for security
      # if not validate_sap_host(connection.host):
      #     raise ValueError(f"Invalid or potentially unsafe SAP host: {sanitize_for_logging(connection.host)}")
      
      # Determine base URL
      # self.base_url = self._build_base_url()


  async def read(self, uri, content_type: str) -> ADTAPICallResponse:
      try:
          print(f"[SAP-CLIENT] Trying to get from URL: {sanitize_for_logging(uri)}")
          logger.info(f"Trying to get from URL: {sanitize_for_logging(uri)}")

          await self.v1_client._ensure_session_valid()

          url = urljoin(self.v1_client.base_url, uri)
                  
          headers = await self.v1_client._get_appropriate_headers()
          headers['Accept'] = content_type
          
          async with self.v1_client.session.get(url, headers=headers) as response:
              xml_content = await response.text()
              if response.status == 200:
                  print(f"[SAP-CLIENT] Data retrieved successfully, length: {validate_numeric_input(len(xml_content), 'length')}")
                  return ADTAPICallResponse(success=True, data=xml_content, status_code=response.status)
              else:
                  logger.error(f"Failed to read from URL: {response.status}")
                  logger.error(xml_content)
                  return ADTAPICallResponse(success=False, error=xml_content, status_code=response.status)
                  
      except Exception as e:
          raise Exception(f"Error reading from URL: {sanitize_for_logging(str(e))}")
      

  async def create(self, request: ADTCreateRequest) -> ObjectOperationResult:
      try:
          print(f"[SAP-CLIENT] Trying to create with URL: {sanitize_for_logging(request.uri)}")
          logger.info(f"Trying to create with URL: {sanitize_for_logging(request.uri)}")

          await self.v1_client._ensure_session_valid()

          url = urljoin(self.v1_client.base_url, request.uri)
                  
          headers = await self.v1_client._get_appropriate_headers()
          headers['Accept'] = '*/*'
          headers['Content-Type'] = request.content_type

          # Ensure we have CSRF token and cookies
          if self.v1_client.csrf_token:
              headers['X-CSRF-Token'] = self.v1_client.csrf_token
          
          params = {"corrNr": quote(request.transport_request)} if request.transport_request else {}
              
          async with self.v1_client.session.post(url, headers=headers, data=request.data, params=params) as response:
              xml_content = await response.text()
              if response.status in [200, 201]:
                  logger.info(f"Successfully created object {sanitize_for_logging(request.name)}")
  
              else:
                  logger.error(f"Failed to create with URL: {response.status}")
                  logger.error(xml_content)
                  return ObjectOperationResult(
                      created=False,
                      syntax_check_passed=False,
                      activated=False,
                      errors=[SAPSyntaxError(line=0, message=f"HTTP {response.status}: {xml_content[:200]}", severity='ERROR')],
                      warnings=[]
              )
                  
          activation_result = await self.v1_client._activate_object_with_details(request.name, request.type)
              
          return ObjectOperationResult(
                  created=True,
                  syntax_check_passed=activation_result.activated,
                  activated=activation_result.activated,
                  errors=activation_result.errors,
                  warnings=activation_result.warnings
              )
  
      except Exception as e:
          raise Exception(f"Error creating in URL: {sanitize_for_logging(str(e))}")
      

  async def update(self, request: ADTCreateRequest) -> ObjectOperationResult:
      try:
          print(f"[SAP-CLIENT] Trying to update with URL: {sanitize_for_logging(request.uri)}/{sanitize_for_logging(request.name)}")
          logger.info(f"Trying to update with URL: {sanitize_for_logging(request.uri)}/{sanitize_for_logging(request.name)}")

          await self.v1_client._ensure_session_valid()

          url = request.uri + '/' + request.name

          lock_info = await self.v1_client._lock_object(url)

          if not lock_info:
                raise Exception("Failed to lock object for update")
          
          logger.info(f"Object locked successfully")

          params = {"lockHandle": lock_info.get('LOCK_HANDLE')} if lock_info.get('LOCK_HANDLE') else {}

          if lock_info.get('CORRNR'):
              params["corrNr"] = lock_info['CORRNR']
                  
          headers = await self.v1_client._get_appropriate_headers()
          headers['Accept'] = '*/*'
          headers['Content-Type'] = request.content_type

          # Ensure we have CSRF token and cookies
          if self.v1_client.csrf_token:
              headers['X-CSRF-Token'] = self.v1_client.csrf_token
                        
          async with self.v1_client.session.put(url, headers=headers, data=request.data, params=params) as response:
              xml_content = await response.text()
              if response.status in [200, 204]:
                  logger.info(f"Successfully updated object {sanitize_for_logging(request.name)}")
  
              else:
                  logger.error(f"Failed to update with URL: {response.status}")
                  logger.error(xml_content)
                  return ObjectOperationResult(
                      created=False,
                      syntax_check_passed=False,
                      activated=False,
                      errors=[SAPSyntaxError(line=0, message=f"HTTP {response.status}: {xml_content[:200]}", severity='ERROR')],
                      warnings=[]
              )
                  
          activation_result = await self.v1_client._activate_object_with_details(request.name, request.type)
              
          return ObjectOperationResult(
                  created=True,
                  syntax_check_passed=activation_result.activated,
                  activated=activation_result.activated,
                  errors=activation_result.errors,
                  warnings=activation_result.warnings
              )
  
      except Exception as e:
          raise Exception(f"Error creating in URL: {sanitize_for_logging(str(e))}")
    