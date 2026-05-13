import { ValidityInfo, ValidityInfoOptions } from '@owf/mdoc';

export interface MdocDocumentDefinition {
  docType: string;
  namespaces: Record<string, Record<string, unknown>>;
  validityInfo: ValidityInfo | ValidityInfoOptions;
}

export { BADGE_DOCTYPE, BADGE_NAMESPACE, getCompanyBadgeDocument } from './badge';
export { MDL_DOCTYPE, MDL_NAMESPACE, getMdlDocument } from './mdl';
export { PID_MDOC_DOCTYPE, PID_MDOC_IT_NAMESPACE, PID_MDOC_NAMESPACE, getPidMdocDocument } from './pid';
