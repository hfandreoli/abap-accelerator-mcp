

from urllib.parse import urljoin, quote
from typing import Dict, Any, List, Optional

from sap_types.sap_types import ADTAPICallResponse, ADTCreateRequest, BaseObjectRequest, CreateObjectRequest, ObjectOperationResult
from pydantic import BaseModel

from sap.sap_client_v2 import SAPADTClient2

from utils.security import (
    sanitize_for_logging, sanitize_for_xml, validate_numeric_input,
    decrypt_from_memory, validate_sap_host, sanitize_file_path
)

import logging
logger = logging.getLogger(__name__)

class BaseObjectHandler:
    def __init__(self, sap_client: SAPADTClient2):
        self.sap_client = sap_client

    @classmethod
    def get_handler(cls, sap_client: SAPADTClient2, object_type: str):
        if object_type.upper() == 'DTEL':
            from sap.data_element_handler import DataElementHandler
            return DataElementHandler(sap_client)
        else:
            return BaseObjectHandler(sap_client)

    async def get_info(self, object_name: str) -> Dict[str, Any]:
        """Get detailed object information"""
       
        uri = f"{self._get_type_uri()}/{quote(object_name)}"
                            
        response = await self.sap_client.read(uri, self._get_content_type())

        retunr_obj = self._parse_info_response(response.data)

        return retunr_obj.dict() if retunr_obj else {}
                    
    async def create(self, args: Dict[str, Any]) -> ObjectOperationResult:

        object_request = self._parse_input_type_args(args)

        # Step 0: Validate object name and get transport information
        validation_result = await self.sap_client.v1_client._validate_object_name_and_get_transport(object_request)

        if not validation_result.get('valid', False):
            error_msg = validation_result.get('error', 'Object validation failed')
            logger.info(f"Object validation was not successful: {error_msg} - continuing with object creation")
            
            # For $TMP package or if validation fails, try to proceed anyway
            if object_request.package_name.upper() == "$TMP":
                logger.info("Proceeding with $TMP package despite validation issue")
            else:
                logger.info("Validation had issues but proceeding with object creation anyway")
                # Don't fail immediately - let the actual creation attempt handle it
        else:
            # Update request with validated transport if available
            if validation_result.get('transport_number') and not object_request.transport_request:
                object_request.transport_request = validation_result['transport_number']
                logger.info(f"Using transport from validation: {sanitize_for_logging(object_request.transport_request)}")

        logger.info(f"Creating object {sanitize_for_logging(object_request.name)} type {sanitize_for_logging(object_request.type)} in package {sanitize_for_logging(object_request.package_name)}")

        create_request = ADTCreateRequest(
            name=object_request.name,
            type=object_request.type,
            uri=self._get_type_uri(),
            content_type=self._get_content_type(),
            package_name=object_request.package_name,
            data=self._build_object_xml(object_request),
            transport_request=object_request.transport_request
        )

        logger.info(f"Sending create request for {sanitize_for_logging(create_request.name)}")
        return await self.sap_client.create(create_request)

    def _get_type_uri(self):
        raise NotImplementedError("Subclasses must implement this method")
    
    def _get_content_type(self):
        raise NotImplementedError("Subclasses must implement this method")
    
    def _parse_info_response(self, xml_content: str) -> BaseModel:
        raise NotImplementedError("Subclasses must implement this method")
    
    def _parse_input_type_args(self, args: Dict[str, Any]) -> BaseModel:
        raise NotImplementedError("Subclasses must implement this method")
    
    def _build_object_xml(self, object_request: BaseModel) -> str:
        raise NotImplementedError("Subclasses must implement this method")
    