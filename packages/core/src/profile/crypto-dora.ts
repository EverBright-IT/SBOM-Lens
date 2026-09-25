import type { ComplianceProfile } from './model';
import { PROFILE_SCHEMA_V5 } from './model';

/**
 * Commission Delegated Regulation (EU) 2024/1774 (the DORA RTS on ICT risk
 * management), Article 7(4): financial entities "create and maintain a
 * register for all certificates and certificate-storing devices for at
 * least ICT assets supporting critical or important functions" and keep it
 * up to date; Article 7(5): they "ensure the prompt renewal of certificates
 * in advance of their expiration". Article 7(1) asks for key management
 * across the whole lifecycle, from generation to destruction.
 *
 * A CBOM can BE that register when it names its certificates and keys with
 * the data the register needs; this profile measures whether it does. What
 * "in advance" means, which assets support critical functions, and whether
 * renewal actually happened are the entity's process, not a file's content.
 */
export const CRYPTO_DORA_PROFILE: ComplianceProfile = {
  schema: PROFILE_SCHEMA_V5,
  name: 'DORA RTS Article 7(4): certificate register',
  specUrl: 'https://eur-lex.europa.eu/eli/reg_del/2024/1774/oj/eng',
  requires: { spec: 'cdx-1.6' },
  description:
    'Measures whether a CycloneDX CBOM carries the data a certificate ' +
    'register under Article 7(4) of Commission Delegated Regulation (EU) ' +
    '2024/1774 (the DORA regulatory technical standard on ICT risk ' +
    'management) needs: the regulation requires financial entities to ' +
    'create and maintain a register for all certificates and ' +
    'certificate-storing devices for at least the ICT assets supporting ' +
    'critical or important functions and keep it up to date (Article 7(4)), ' +
    'and to ensure the prompt renewal of certificates in advance of their ' +
    'expiration (Article 7(5)); Article 7(1) adds key management through ' +
    'the whole lifecycle. The meters cover ' +
    'certificates (subject, issuer, validity end, lifecycle state, signature ' +
    'algorithm linked) and keys and other material (lifecycle state, ' +
    'expiration, how and where the material is secured, which is the ' +
    'certificate-storing device the register asks for). Nothing gates ' +
    'except the format baseline, because which assets support critical or ' +
    'important functions, what counts as renewal in advance, and whether ' +
    'renewal happened are the process of the entity, not the content of a file. A ' +
    'BOM without certificates or keys reads none in scope.',
  checks: [
    { id: 'certificate-subject', type: 'crypto-coverage', field: 'certificateSubject', assetTypes: ['certificate'], label: 'Certificates: subject stated' },
    { id: 'certificate-issuer', type: 'crypto-coverage', field: 'certificateIssuer', assetTypes: ['certificate'], label: 'Certificates: issuer stated' },
    { id: 'certificate-validity', type: 'crypto-coverage', field: 'certificateValidity', assetTypes: ['certificate'], label: 'Certificates: validity end stated (the date renewal must precede)' },
    { id: 'certificate-state', type: 'crypto-coverage', field: 'certificateState', assetTypes: ['certificate'], label: 'Certificates: lifecycle state stated' },
    { id: 'certificate-signature', type: 'crypto-coverage', field: 'certificateSignature', assetTypes: ['certificate'], label: 'Certificates: signature algorithm linked' },
    { id: 'material-state', type: 'crypto-coverage', field: 'materialState', assetTypes: ['related-crypto-material'], label: 'Keys and material: lifecycle state stated' },
    { id: 'material-expiration', type: 'crypto-coverage', field: 'materialExpiration', assetTypes: ['related-crypto-material'], label: 'Keys and material: expiration stated' },
    { id: 'material-secured-by', type: 'crypto-coverage', field: 'materialSecuredBy', assetTypes: ['related-crypto-material'], label: 'Keys and material: storage mechanism stated (HSM, TPM, software, ...)' },
  ],
};
