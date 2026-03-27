from urllib.parse import urljoin, quote
from typing import Dict, Any, List, Optional

from utils.xml_utils import safe_parse_xml
from sap_types.sap_types import DataElementInfo, DataElementRequest
from sap.base_object_handler import BaseObjectHandler
from utils.security import (
    sanitize_for_logging, sanitize_for_xml, validate_numeric_input,
    decrypt_from_memory, validate_sap_host, sanitize_file_path
)

import logging
logger = logging.getLogger(__name__)

class DataElementHandler(BaseObjectHandler):
    
    def _get_type_uri(self):
        return '/sap/bc/adt/ddic/dataelements'
    
    def _get_content_type(self):
        return 'application/vnd.sap.adt.dataelements.v2+xml'
    
    def _parse_info_response(self, xml_content: str) -> Optional[DataElementInfo]:
        """Parse data element info from XML response"""

        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                return None

            ns_core = '{http://www.sap.com/adt/core}'
            ns_dtel = '{http://www.sap.com/adt/dictionary/dataelements}'
            
            name = root.get(ns_core+'name', '')
            description = root.get(ns_core+'description', '')
            created_by = root.get(ns_core+'createdBy', '')
            created_at = root.get(ns_core+'createdAt', '')
            changed_by = root.get(ns_core+'changedBy', '')
            changed_at = root.get(ns_core+'changedAt', '')

            package_elem = root.find(ns_core+'packageRef')
            package_name = package_elem.get(ns_core+'name', '') if package_elem is not None else ''

            dtel_elem = root.find(ns_dtel+'dataElement')

            domain_name_elem = dtel_elem.find(ns_dtel+'typeName')
            domain_name = domain_name_elem.text.strip() if domain_name_elem is not None and domain_name_elem.text else ''

            data_type_elem = dtel_elem.find(ns_dtel+'dataType')
            data_type = data_type_elem.text.strip() if data_type_elem is not None and data_type_elem.text else ''

            length_elem = dtel_elem.find(ns_dtel+'dataTypeLength')
            length = length_elem.text.strip() if length_elem is not None and length_elem.text else ''

            decimals_elem = dtel_elem.find(ns_dtel+'dataTypeDecimals')
            decimals = decimals_elem.text.strip() if decimals_elem is not None and decimals_elem.text else ''

            short_label_elem = dtel_elem.find(ns_dtel+'shortFieldLabel')
            short_label = short_label_elem.text.strip() if short_label_elem is not None and short_label_elem.text else ''

            medium_label_elem = dtel_elem.find(ns_dtel+'mediumFieldLabel')
            medium_label = medium_label_elem.text.strip() if medium_label_elem is not None and medium_label_elem.text else ''

            long_label_elem = dtel_elem.find(ns_dtel+'longFieldLabel')
            long_label = long_label_elem.text.strip() if long_label_elem is not None and long_label_elem.text else ''

            heading_label_elem = dtel_elem.find(ns_dtel+'headingFieldLabel')
            heading_label = heading_label_elem.text.strip() if heading_label_elem is not None and heading_label_elem.text else ''

            field_labels = {
                "short": short_label,
                "medium": medium_label,
                "long": long_label,
                "heading": heading_label
            }

            return DataElementInfo(
                name=name,
                description=description,
                package_name=package_name,
                domain_name=domain_name,
                data_type=data_type,
                length=length,
                decimals=decimals,
                field_labels=field_labels,
                created_by=created_by,
                created_at=created_at,
                changed_by=changed_by,
                changed_at=changed_at
            )
                    
        except Exception as e:
            logger.error(f"Error parsing data element info XML: {sanitize_for_logging(str(e))}")
            return None

    def _parse_input_type_args(self, args: Dict[str, Any]) -> DataElementRequest:
        return DataElementRequest(
            name=args.get('name', ''),
            type=args.get('type', ''),
            description=args.get('description', ''),
            package_name=args.get('package_name', '') or '$TMP',
            data_type=args.get('data_type'),
            domain_name=args.get('domain_name'),
            length=args.get('length'),
            decimals=args.get('decimals'),
            field_labels={
                'short': args.get('short_label'),
                'medium': args.get('medium_label'),
                'long': args.get('long_label'),
                'heading': args.get('heading_label')
            }
          )
    
    def _build_object_xml(self, object_request: DataElementInfo) -> str:
        return  ( 
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<blue:wbobj xmlns:adtcore="http://www.sap.com/adt/core" xmlns:blue="http://www.sap.com/wbobj/dictionary/dtel" '
            'adtcore:description="' f'{sanitize_for_xml(object_request.description)}' '" '
            'adtcore:language="EN" adtcore:name="' f'{sanitize_for_xml(object_request.name)}' '" adtcore:type="DTEL/DE" adtcore:masterLanguage="EN">'
            '<adtcore:packageRef adtcore:type="DEVC/K" adtcore:name="' f'{sanitize_for_xml(object_request.package_name)}' '"/>'
            '<dtel:dataElement xmlns:dtel="http://www.sap.com/adt/dictionary/dataelements">'
            '<dtel:typeKind>' f'{"domain" if object_request.domain_name else "predefinedAbapType"}' '</dtel:typeKind>'
            '<dtel:typeName/>'
            '<dtel:dataType>' f'{sanitize_for_xml(object_request.data_type)}' '</dtel:dataType>'
            '<dtel:dataTypeLength>' f'{object_request.length or ""}' '</dtel:dataTypeLength>'
            '<dtel:dataTypeDecimals>' f'{object_request.decimals or ""}' '</dtel:dataTypeDecimals>'
            '<dtel:shortFieldLabel>' f'{sanitize_for_xml(object_request.field_labels.get("short"))}' '</dtel:shortFieldLabel>'
            '<dtel:shortFieldLength/>'
            '<dtel:shortFieldMaxLength/>'
            '<dtel:mediumFieldLabel>' f'{sanitize_for_xml(object_request.field_labels.get("medium"))}' '</dtel:mediumFieldLabel>'
            '<dtel:mediumFieldLength/>'
            '<dtel:mediumFieldMaxLength/>'
            '<dtel:longFieldLabel>' f'{sanitize_for_xml(object_request.field_labels.get("long"))}' '</dtel:longFieldLabel>'
            '<dtel:longFieldLength/>'
            '<dtel:longFieldMaxLength/>'
            '<dtel:headingFieldLabel>' f'{sanitize_for_xml(object_request.field_labels.get("heading"))}' '</dtel:headingFieldLabel>'
            '<dtel:headingFieldLength/>'
            '<dtel:headingFieldMaxLength/>'
            '<dtel:searchHelp/>'
            '<dtel:searchHelpParameter/>'
            '<dtel:setGetParameter/>'
            '<dtel:defaultComponentName/>'
            '<dtel:deactivateInputHistory>false</dtel:deactivateInputHistory>'
            '<dtel:changeDocument>false</dtel:changeDocument>'
            '<dtel:leftToRightDirection>false</dtel:leftToRightDirection>'
            '<dtel:deactivateBIDIFiltering>false</dtel:deactivateBIDIFiltering>'
            '</dtel:dataElement>'
            '</blue:wbobj>'
        )
    