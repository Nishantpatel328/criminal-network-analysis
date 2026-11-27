/**
 * Fictional demo dataset. Every name, number, plate and account is invented.
 * Shapes mirror src/types so a real backend can return identical JSON later.
 */
import type {
  Alert, Case, CDRRecord, DataSource, Entity, IntelEvent, InvestigatorProfile,
  LocationRecord, Relationship, Transaction,
} from '../../types/models';

export const investigators: InvestigatorProfile[] = [
  { id: 'U-1', name: 'Ayesha Rahman', email: 'a.rahman@intel.demo', badge: 'CTU-4471', unit: 'CTU — Joint Task Force', role: 'Senior Investigator', phone: '+250 700 114 210' },
  { id: 'U-2', name: 'Daniel Mensah', email: 'd.mensah@intel.demo', badge: 'FIU-2210', unit: 'Financial Intelligence Unit', role: 'Financial Intelligence Analyst', phone: '+250 700 552 908' },
  { id: 'U-3', name: 'Sara Okafor', email: 's.okafor@intel.demo', badge: 'FO-8834', unit: 'Field Operations', role: 'Field Operations Lead', phone: '+250 700 901 733' },
];

const T = (iso: string) => iso;

export const entities: Entity[] = [
  // ---- persons ----
  { id: 'P-1001', type: 'PERSON', label: 'Viktor Sarek', subtype: 'Suspect — Principal', status: 'WATCHLIST', riskScore: 91, aliases: ['V. Sarek', 'The Broker'], attributes: { dob: '1974-03-12', nationality: 'Ruritanian', nationalId: 'RU-77410233', occupation: 'Import/export consultant', addressId: 'L-101' }, createdAt: T('2026-01-14T09:00:00Z'), updatedAt: T('2026-09-08T11:20:00Z') },
  { id: 'P-1002', type: 'PERSON', label: 'Amara Diallo', subtype: 'Suspect — Facilitator', status: 'ACTIVE', riskScore: 74, aliases: ['A. Diallo'], attributes: { dob: '1988-07-30', nationality: 'Coastal Republic', nationalId: 'CR-55600912', occupation: 'Freight forwarding agent', addressId: 'L-102' }, createdAt: T('2026-01-20T10:00:00Z'), updatedAt: T('2026-09-05T16:40:00Z') },
  { id: 'P-1003', type: 'PERSON', label: 'Tomas Reyes', subtype: 'Person of Interest', status: 'ACTIVE', riskScore: 63, aliases: ['T. Reyes'], attributes: { dob: '1990-11-02', nationality: 'Meridian Federation', nationalId: 'MF-90122345', occupation: 'Used vehicle dealer', addressId: 'L-103' }, createdAt: T('2026-02-02T08:30:00Z'), updatedAt: T('2026-08-30T09:12:00Z') },
  { id: 'P-1004', type: 'PERSON', label: 'Nadia Petrova', subtype: 'Suspect — Financial', status: 'FLAGGED', riskScore: 82, aliases: ['N. Petrova'], attributes: { dob: '1981-01-25', nationality: 'Ruritanian', nationalId: 'RU-55218790', occupation: 'Accountant', addressId: 'L-104' }, createdAt: T('2026-01-15T13:00:00Z'), updatedAt: T('2026-09-09T08:05:00Z') },
  { id: 'P-1005', type: 'PERSON', label: 'Samuel Odeyemi', subtype: 'Witness', status: 'ACTIVE', riskScore: 22, aliases: [], attributes: { dob: '1995-05-17', nationality: 'Coastal Republic', nationalId: 'CR-77812340', occupation: 'Warehouse supervisor', addressId: 'L-105' }, createdAt: T('2026-03-11T14:00:00Z'), updatedAt: T('2026-06-21T10:00:00Z') },
  { id: 'P-1006', type: 'PERSON', label: 'Iris Lindqvist', subtype: 'Person of Interest', status: 'WATCHLIST', riskScore: 68, aliases: ['I. Lindqvist'], attributes: { dob: '1979-09-08', nationality: 'Nordland', nationalId: 'ND-33412098', occupation: 'Shipping broker', addressId: 'L-106' }, createdAt: T('2026-02-19T09:45:00Z'), updatedAt: T('2026-09-02T13:55:00Z') },
  { id: 'P-1007', type: 'PERSON', label: 'Kwame Asante', subtype: 'Suspect — Logistics', status: 'DETAINED', riskScore: 77, aliases: ['K. Asante'], attributes: { dob: '1985-12-01', nationality: 'Coastal Republic', nationalId: 'CR-66124007', occupation: 'Truck fleet owner', addressId: 'L-107' }, createdAt: T('2026-01-18T11:00:00Z'), updatedAt: T('2026-08-25T17:30:00Z') },
  { id: 'P-1008', type: 'PERSON', label: 'Elena Voss', subtype: 'Associate', status: 'ACTIVE', riskScore: 41, aliases: ['E. Voss'], attributes: { dob: '1992-04-21', nationality: 'Meridian Federation', nationalId: 'MF-88331209', occupation: 'Notary clerk', addressId: 'L-108' }, createdAt: T('2026-04-02T10:20:00Z'), updatedAt: T('2026-07-14T09:00:00Z') },
  // ---- phones ----
  { id: 'PH-2001', type: 'PHONE', label: '+250 788 412 091', subtype: 'Mobile — prepaid', status: 'ACTIVE', riskScore: 88, aliases: ['IMEI 35-209900-447721-3'], attributes: { imei: '352099004477213', imsi: '6400214477213', operator: 'KivuTel', registeredTo: 'P-1001' }, createdAt: T('2026-01-14T09:00:00Z'), updatedAt: T('2026-09-10T06:30:00Z') },
  { id: 'PH-2002', type: 'PHONE', label: '+250 733 908 554', subtype: 'Mobile — prepaid', status: 'ACTIVE', riskScore: 61, aliases: ['IMEI 86-441200-883410-1'], attributes: { imei: '864412008834101', imsi: '6400218834101', operator: 'KivuTel', registeredTo: 'P-1002' }, createdAt: T('2026-01-20T10:00:00Z'), updatedAt: T('2026-09-04T12:00:00Z') },
  { id: 'PH-2003', type: 'PHONE', label: '+250 725 110 332', subtype: 'Mobile — contract', status: 'INACTIVE', riskScore: 35, aliases: [], attributes: { imei: '351756110009884', imsi: '6400211000988', operator: 'KivuTel', registeredTo: 'P-1003' }, createdAt: T('2026-02-02T08:30:00Z'), updatedAt: T('2026-06-01T00:00:00Z') },
  { id: 'PH-2004', type: 'PHONE', label: '+31 6 4420 8917', subtype: 'Mobile — roaming', status: 'ACTIVE', riskScore: 79, aliases: ['burner cycle 3'], attributes: { imei: '990004827710245', imsi: '2041600427710', operator: 'NederMobiel', registeredTo: 'P-1004' }, createdAt: T('2026-01-15T13:00:00Z'), updatedAt: T('2026-09-09T07:45:00Z') },
  { id: 'PH-2005', type: 'PHONE', label: '+250 790 556 710', subtype: 'Mobile — prepaid', status: 'FLAGGED', riskScore: 72, aliases: [], attributes: { imei: '354990881200341', imsi: '6400218120034', operator: 'KivuTel', registeredTo: 'P-1007' }, createdAt: T('2026-01-18T11:00:00Z'), updatedAt: T('2026-08-24T15:10:00Z') },
  { id: 'PH-2006', type: 'PHONE', label: '+46 70 552 0138', subtype: 'Mobile — contract', status: 'ACTIVE', riskScore: 44, aliases: [], attributes: { imei: '358240066112390', imsi: '2400106611239', operator: 'NordCell', registeredTo: 'P-1006' }, createdAt: T('2026-02-19T09:45:00Z'), updatedAt: T('2026-08-31T11:00:00Z') },
  // ---- vehicles ----
  { id: 'V-3001', type: 'VEHICLE', label: 'CRA 4471 BQ', subtype: 'Box truck — 7.5t', status: 'ACTIVE', riskScore: 70, aliases: ['VIN NLRT7AXT4PD220118'], attributes: { vin: 'NLRT7AXT4PD220118', make: 'Voltra VT75', color: 'White', owner: 'P-1007', orgOwner: 'ORG-4002' }, createdAt: T('2026-01-18T11:00:00Z'), updatedAt: T('2026-08-25T17:30:00Z') },
  { id: 'V-3002', type: 'VEHICLE', label: 'RUR 88-12 KA', subtype: 'Sedan', status: 'WATCHLIST', riskScore: 58, aliases: ['VIN RURN1SED9MM441207'], attributes: { vin: 'RURN1SED9MM441207', make: 'Meridian M4', color: 'Grey', owner: 'P-1001' }, createdAt: T('2026-01-14T09:00:00Z'), updatedAt: T('2026-09-06T09:20:00Z') },
  { id: 'V-3003', type: 'VEHICLE', label: 'CRA 9030 TT', subtype: 'Cargo van', status: 'ACTIVE', riskScore: 33, aliases: [], attributes: { vin: 'COAS2VAN2KA990011', make: 'Harbor H200', color: 'Blue', owner: 'P-1002' }, createdAt: T('2026-01-20T10:00:00Z'), updatedAt: T('2026-05-19T08:00:00Z') },
  { id: 'V-3004', type: 'VEHICLE', label: 'ND 5X 4410', subtype: 'Motorcycle', status: 'INACTIVE', riskScore: 25, aliases: [], attributes: { vin: 'NORD3MOT7LL552100', make: 'Tundra 650', color: 'Black', owner: 'P-1006' }, createdAt: T('2026-02-19T09:45:00Z'), updatedAt: T('2026-07-01T00:00:00Z') },
  // ---- organizations ----
  { id: 'ORG-4001', type: 'ORGANIZATION', label: 'Meridian Trade & Freight Ltd', subtype: 'Freight forwarding', status: 'FLAGGED', riskScore: 76, aliases: ['MTF Ltd'], attributes: { registrationNo: 'MF-REG-88412', director: 'P-1002', sector: 'Logistics', addressId: 'L-109' }, createdAt: T('2026-01-20T10:00:00Z'), updatedAt: T('2026-09-05T16:40:00Z') },
  { id: 'ORG-4002', type: 'ORGANIZATION', label: 'Asante Haulage Co', subtype: 'Road transport', status: 'ACTIVE', riskScore: 64, aliases: [], attributes: { registrationNo: 'CR-REG-12077', director: 'P-1007', sector: 'Transport', addressId: 'L-107' }, createdAt: T('2026-01-18T11:00:00Z'), updatedAt: T('2026-08-20T10:00:00Z') },
  { id: 'ORG-4003', type: 'ORGANIZATION', label: 'Baltic Shell Holdings', subtype: 'Holding company', status: 'WATCHLIST', riskScore: 85, aliases: ['BSH Group'], attributes: { registrationNo: 'ND-REG-33419', director: 'P-1006', sector: 'Finance', addressId: 'L-106' }, createdAt: T('2026-02-19T09:45:00Z'), updatedAt: T('2026-09-02T13:55:00Z') },
  { id: 'ORG-4004', type: 'ORGANIZATION', label: 'Reyes Auto Exchange', subtype: 'Used vehicle sales', status: 'ACTIVE', riskScore: 38, aliases: [], attributes: { registrationNo: 'MF-REG-55120', director: 'P-1003', sector: 'Retail', addressId: 'L-103' }, createdAt: T('2026-02-02T08:30:00Z'), updatedAt: T('2026-06-11T14:00:00Z') },
  // ---- accounts ----
  { id: 'AC-5001', type: 'ACCOUNT', label: 'ACC ****7712 — Coastal Union Bank', subtype: 'Business checking', status: 'FLAGGED', riskScore: 86, aliases: ['IBAN CR12 4480 0077 1231'], attributes: { iban: 'CR12 4480 0077 1231', bank: 'Coastal Union Bank', holder: 'ORG-4001', opened: '2019-04-11' }, createdAt: T('2026-01-20T10:00:00Z'), updatedAt: T('2026-09-09T08:00:00Z') },
  { id: 'AC-5002', type: 'ACCOUNT', label: 'ACC ****3348 — NordBank', subtype: 'Personal savings', status: 'WATCHLIST', riskScore: 81, aliases: ['IBAN ND09 7700 3348 112'], attributes: { iban: 'ND09 7700 3348 112', bank: 'NordBank', holder: 'P-1004', opened: '2021-08-02' }, createdAt: T('2026-01-15T13:00:00Z'), updatedAt: T('2026-09-09T08:05:00Z') },
  { id: 'AC-5003', type: 'ACCOUNT', label: 'ACC ****9901 — Ruritan Central', subtype: 'Business checking', status: 'ACTIVE', riskScore: 52, aliases: [], attributes: { iban: 'RU44 1200 9901 776', bank: 'Ruritan Central', holder: 'P-1001', opened: '2017-01-19' }, createdAt: T('2026-01-14T09:00:00Z'), updatedAt: T('2026-08-15T12:00:00Z') },
  { id: 'AC-5004', type: 'ACCOUNT', label: 'ACC ****5520 — Kivu Microfinance', subtype: 'Mobile wallet', status: 'ACTIVE', riskScore: 47, aliases: [], attributes: { iban: 'CR77 6600 5520 091', bank: 'Kivu Microfinance', holder: 'P-1007', opened: '2022-03-30' }, createdAt: T('2026-01-18T11:00:00Z'), updatedAt: T('2026-07-28T09:00:00Z') },
  { id: 'AC-5005', type: 'ACCOUNT', label: 'ACC ****0817 — Harbor Trust', subtype: 'Escrow', status: 'FLAGGED', riskScore: 73, aliases: [], attributes: { iban: 'MF21 3300 0817 445', bank: 'Harbor Trust', holder: 'ORG-4003', opened: '2023-11-08' }, createdAt: T('2026-02-19T09:45:00Z'), updatedAt: T('2026-09-01T10:30:00Z') },
  // ---- events as graph nodes ----
  { id: 'EV-6001', type: 'EVENT', label: 'Container inspection — Pier 9', subtype: 'Port event', status: 'CLOSED', riskScore: 55, aliases: [], attributes: { occurredAt: '2026-08-18T06:40:00Z', outcome: 'Contraband layer discovered', locationId: 'L-109' }, createdAt: T('2026-08-18T08:00:00Z'), updatedAt: T('2026-08-18T08:00:00Z') },
  { id: 'EV-6002', type: 'EVENT', label: 'Controlled delivery — Warehouse 14', subtype: 'Operation', status: 'ACTIVE', riskScore: 78, aliases: [], attributes: { occurredAt: '2026-09-07T21:15:00Z', outcome: 'In progress', locationId: 'L-105' }, createdAt: T('2026-09-07T21:20:00Z'), updatedAt: T('2026-09-10T06:00:00Z') },
  { id: 'EV-6003', type: 'EVENT', label: 'Border crossing — Kalm Pass', subtype: 'Border event', status: 'CLOSED', riskScore: 62, aliases: [], attributes: { occurredAt: '2026-08-30T03:10:00Z', outcome: 'Vehicle flagged, released in error', locationId: 'L-110' }, createdAt: T('2026-08-30T04:00:00Z'), updatedAt: T('2026-09-02T09:00:00Z') },
];

export const locations: LocationRecord[] = [
  { id: 'L-101', name: 'Sarek residence', type: 'ADDRESS', address: '14 Vesper Lane, Old Port District', lat: -1.2921, lng: 36.8219, notes: 'Confirmed residence, surveillance authorized' },
  { id: 'L-102', name: 'Diallo apartment', type: 'ADDRESS', address: '7 Harbor Walk, Block C', lat: -1.3044, lng: 36.8472 },
  { id: 'L-103', name: 'Reyes Auto Exchange lot', type: 'BUSINESS', address: '201 Meridian Road', lat: 12.1223, lng: 15.0551 },
  { id: 'L-104', name: 'Petrova residence', type: 'ADDRESS', address: 'Kerkstraat 88, Amsterdam (fictional)', lat: 52.3676, lng: 4.9041 },
  { id: 'L-105', name: 'Warehouse 14', type: 'BUSINESS', address: 'Dockside Industrial Zone, Unit 14', lat: -1.3311, lng: 36.8623, notes: 'Controlled delivery in progress' },
  { id: 'L-106', name: 'Baltic Shell office', type: 'BUSINESS', address: '11 Harbor Ring, Suite 400', lat: 59.3293, lng: 18.0686 },
  { id: 'L-107', name: 'Asante Haulage depot', type: 'BUSINESS', address: '44 Fleet Yard, Industrial Crescent', lat: -1.2765, lng: 36.9054 },
  { id: 'L-108', name: 'Voss residence', type: 'ADDRESS', address: '9 Linden Court', lat: 12.1048, lng: 15.0382 },
  { id: 'L-109', name: 'Port of Meridian — Pier 9', type: 'BUSINESS', address: 'Meridian Freeport Zone', lat: 12.0513, lng: 15.0965, notes: 'Container inspection 18 Aug' },
  { id: 'L-110', name: 'Kalm Pass border post', type: 'BORDER', address: 'Northern corridor, km 212', lat: -0.9821, lng: 36.4510 },
  { id: 'L-111', name: 'Cell site KIV-114', type: 'CELL_SITE', address: 'Ridge antenna, Sector 4', lat: -1.2811, lng: 36.8455 },
  { id: 'L-112', name: 'Safehouse (suspected)', type: 'SAFEHOUSE', address: '3 Albacore Close', lat: -1.3156, lng: 36.8301, notes: 'Anonymous tip, unverified' },
];

export const relationships: Relationship[] = [
  { id: 'R-001', sourceId: 'P-1001', targetId: 'PH-2001', type: 'OWNERSHIP', label: 'Registered user', strength: 10, confidence: 'HIGH', source: 'Registry', firstSeen: '2026-01-14', lastSeen: '2026-09-10' },
  { id: 'R-002', sourceId: 'P-1002', targetId: 'PH-2002', type: 'OWNERSHIP', label: 'Registered user', strength: 10, confidence: 'HIGH', source: 'Registry', firstSeen: '2026-01-20', lastSeen: '2026-09-04' },
  { id: 'R-003', sourceId: 'P-1001', targetId: 'P-1002', type: 'ASSOCIATION', label: 'Frequent contact — 47 calls / 30d', strength: 9, confidence: 'HIGH', source: 'CDR', firstSeen: '2026-02-01', lastSeen: '2026-09-08' },
  { id: 'R-004', sourceId: 'PH-2001', targetId: 'PH-2002', type: 'COMMUNICATION', label: 'Voice/SMS traffic', strength: 9, confidence: 'HIGH', source: 'CDR', firstSeen: '2026-02-01', lastSeen: '2026-09-08' },
  { id: 'R-005', sourceId: 'P-1001', targetId: 'P-1004', type: 'FINANCIAL', label: 'Layered transfers AC-5003/AC-5002', strength: 8, confidence: 'MEDIUM', source: 'Bank Registry', firstSeen: '2026-03-12', lastSeen: '2026-09-01' },
  { id: 'R-006', sourceId: 'AC-5003', targetId: 'AC-5002', type: 'FINANCIAL', label: '17 transfers, structuring pattern', strength: 8, confidence: 'HIGH', source: 'Bank Registry', firstSeen: '2026-03-12', lastSeen: '2026-09-01' },
  { id: 'R-007', sourceId: 'P-1004', targetId: 'AC-5002', type: 'OWNERSHIP', label: 'Account holder', strength: 10, confidence: 'HIGH', source: 'Bank Registry', firstSeen: '2021-08-02', lastSeen: '2026-09-09' },
  { id: 'R-008', sourceId: 'P-1001', targetId: 'AC-5003', type: 'OWNERSHIP', label: 'Account holder', strength: 10, confidence: 'HIGH', source: 'Bank Registry', firstSeen: '2017-01-19', lastSeen: '2026-08-15' },
  { id: 'R-009', sourceId: 'P-1002', targetId: 'ORG-4001', type: 'EMPLOYMENT', label: 'Director', strength: 9, confidence: 'HIGH', source: 'Registry', firstSeen: '2020-06-01', lastSeen: '2026-09-05' },
  { id: 'R-010', sourceId: 'ORG-4001', targetId: 'AC-5001', type: 'OWNERSHIP', label: 'Corporate account', strength: 10, confidence: 'HIGH', source: 'Bank Registry', firstSeen: '2019-04-11', lastSeen: '2026-09-09' },
  { id: 'R-011', sourceId: 'P-1007', targetId: 'ORG-4002', type: 'EMPLOYMENT', label: 'Owner/director', strength: 10, confidence: 'HIGH', source: 'Registry', firstSeen: '2016-01-01', lastSeen: '2026-08-20' },
  { id: 'R-012', sourceId: 'ORG-4002', targetId: 'V-3001', type: 'OWNERSHIP', label: 'Fleet vehicle', strength: 9, confidence: 'HIGH', source: 'ANPR/Registry', firstSeen: '2019-09-14', lastSeen: '2026-08-25' },
  { id: 'R-013', sourceId: 'P-1001', targetId: 'V-3002', type: 'OWNERSHIP', label: 'Registered owner', strength: 10, confidence: 'HIGH', source: 'Registry', firstSeen: '2020-11-03', lastSeen: '2026-09-06' },
  { id: 'R-014', sourceId: 'V-3001', targetId: 'L-110', type: 'SIGHTING', label: 'ANPR hit at border post', strength: 7, confidence: 'HIGH', source: 'ANPR', firstSeen: '2026-08-30', lastSeen: '2026-08-30' },
  { id: 'R-015', sourceId: 'P-1006', targetId: 'ORG-4003', type: 'EMPLOYMENT', label: 'Director', strength: 9, confidence: 'HIGH', source: 'Registry', firstSeen: '2021-02-15', lastSeen: '2026-09-02' },
  { id: 'R-016', sourceId: 'ORG-4003', targetId: 'AC-5005', type: 'OWNERSHIP', label: 'Escrow account', strength: 10, confidence: 'HIGH', source: 'Bank Registry', firstSeen: '2023-11-08', lastSeen: '2026-09-01' },
  { id: 'R-017', sourceId: 'P-1006', targetId: 'PH-2006', type: 'OWNERSHIP', label: 'Registered user', strength: 10, confidence: 'HIGH', source: 'Registry', firstSeen: '2026-02-19', lastSeen: '2026-08-31' },
  { id: 'R-018', sourceId: 'P-1006', targetId: 'P-1004', type: 'ASSOCIATION', label: '11 calls; shared Baltic Shell entity', strength: 6, confidence: 'MEDIUM', source: 'CDR', firstSeen: '2026-04-18', lastSeen: '2026-08-29' },
  { id: 'R-019', sourceId: 'AC-5005', targetId: 'AC-5002', type: 'FINANCIAL', label: 'Two escrow payouts', strength: 7, confidence: 'MEDIUM', source: 'Bank Registry', firstSeen: '2026-06-22', lastSeen: '2026-08-14' },
  { id: 'R-020', sourceId: 'P-1003', targetId: 'V-3003', type: 'OWNERSHIP', label: 'Registered owner', strength: 9, confidence: 'HIGH', source: 'Registry', firstSeen: '2021-05-20', lastSeen: '2026-05-19' },
  { id: 'R-021', sourceId: 'P-1003', targetId: 'ORG-4004', type: 'EMPLOYMENT', label: 'Owner', strength: 10, confidence: 'HIGH', source: 'Registry', firstSeen: '2018-03-01', lastSeen: '2026-06-11' },
  { id: 'R-022', sourceId: 'P-1002', targetId: 'P-1007', type: 'ASSOCIATION', label: 'Logistics coordination — 23 calls / 30d', strength: 7, confidence: 'HIGH', source: 'CDR', firstSeen: '2026-03-02', lastSeen: '2026-09-07' },
  { id: 'R-023', sourceId: 'PH-2002', targetId: 'PH-2005', type: 'COMMUNICATION', label: 'Voice traffic', strength: 7, confidence: 'HIGH', source: 'CDR', firstSeen: '2026-03-02', lastSeen: '2026-09-07' },
  { id: 'R-024', sourceId: 'P-1007', targetId: 'PH-2005', type: 'OWNERSHIP', label: 'Registered user', strength: 10, confidence: 'HIGH', source: 'Registry', firstSeen: '2026-01-18', lastSeen: '2026-08-24' },
  { id: 'R-025', sourceId: 'P-1007', targetId: 'AC-5004', type: 'OWNERSHIP', label: 'Wallet holder', strength: 10, confidence: 'HIGH', source: 'Bank Registry', firstSeen: '2022-03-30', lastSeen: '2026-07-28' },
  { id: 'R-026', sourceId: 'P-1001', targetId: 'L-101', type: 'CO_RESIDENCE', label: 'Confirmed residence', strength: 9, confidence: 'HIGH', source: 'Registry', firstSeen: '2019-07-01', lastSeen: '2026-09-08' },
  { id: 'R-027', sourceId: 'P-1001', targetId: 'L-112', type: 'SIGHTING', label: 'Anonymous tip — possible meetings', strength: 4, confidence: 'LOW', source: 'TIP', firstSeen: '2026-08-19', lastSeen: '2026-08-19' },
  { id: 'R-028', sourceId: 'P-1001', targetId: 'EV-6001', type: 'SIGHTING', label: 'Present at container inspection', strength: 5, confidence: 'MEDIUM', source: 'Port Authority', firstSeen: '2026-08-18', lastSeen: '2026-08-18' },
  { id: 'R-029', sourceId: 'P-1002', targetId: 'EV-6001', type: 'SIGHTING', label: 'Present at container inspection', strength: 6, confidence: 'HIGH', source: 'Port Authority', firstSeen: '2026-08-18', lastSeen: '2026-08-18' },
  { id: 'R-030', sourceId: 'V-3001', targetId: 'L-105', type: 'SIGHTING', label: 'ANPR + witness at Warehouse 14', strength: 8, confidence: 'HIGH', source: 'ANPR/TIP', firstSeen: '2026-09-06', lastSeen: '2026-09-07' },
  { id: 'R-031', sourceId: 'P-1005', targetId: 'L-105', type: 'EMPLOYMENT', label: 'Works at warehouse', strength: 8, confidence: 'HIGH', source: 'Registry', firstSeen: '2023-01-09', lastSeen: '2026-09-07' },
  { id: 'R-032', sourceId: 'P-1004', targetId: 'L-106', type: 'SIGHTING', label: 'Visited Baltic Shell office', strength: 5, confidence: 'MEDIUM', source: 'TIP', firstSeen: '2026-08-22', lastSeen: '2026-08-22' },
  { id: 'R-033', sourceId: 'P-1008', targetId: 'ORG-4004', type: 'EMPLOYMENT', label: 'Notary for vehicle transfers', strength: 6, confidence: 'HIGH', source: 'Registry', firstSeen: '2022-09-12', lastSeen: '2026-06-11' },
  { id: 'R-034', sourceId: 'P-1008', targetId: 'P-1003', type: 'FAMILY', label: 'Cousin', strength: 5, confidence: 'MEDIUM', source: 'Registry', firstSeen: '2022-09-12', lastSeen: '2026-06-11' },
  { id: 'R-035', sourceId: 'PH-2001', targetId: 'L-111', type: 'SIGHTING', label: 'Cell site attachment pattern', strength: 6, confidence: 'MEDIUM', source: 'CDR', firstSeen: '2026-06-01', lastSeen: '2026-09-10' },
  { id: 'R-036', sourceId: 'P-1002', targetId: 'L-109', type: 'EMPLOYMENT', label: 'MTF operates at Pier 9', strength: 7, confidence: 'HIGH', source: 'Registry', firstSeen: '2020-06-01', lastSeen: '2026-09-05' },
  { id: 'R-037', sourceId: 'AC-5001', targetId: 'AC-5005', type: 'FINANCIAL', label: 'Invoice-chain transfers', strength: 6, confidence: 'MEDIUM', source: 'Bank Registry', firstSeen: '2026-05-10', lastSeen: '2026-08-30' },
  { id: 'R-038', sourceId: 'P-1006', targetId: 'L-110', type: 'TRAVEL', label: 'Border crossing record', strength: 5, confidence: 'MEDIUM', source: 'Border Registry', firstSeen: '2026-08-30', lastSeen: '2026-08-30' },
];

export const cases: Case[] = [
  { id: 'C-2026-014', code: 'OP NIGHTHARBOR', title: 'Cross-border smuggling cell — Northern corridor', status: 'ACTIVE', priority: 'CRITICAL', leadInvestigatorId: 'U-1', openedAt: '2026-01-14', updatedAt: '2026-09-10', summary: 'Coordinated smuggling network moving concealed cargo through Meridian Freeport and the Kalm Pass corridor. Central figures: Sarek (coordination), Diallo (freight), Asante (transport).', entityIds: ['P-1001', 'P-1002', 'P-1004', 'P-1006', 'P-1007', 'PH-2001', 'PH-2002', 'PH-2005', 'V-3001', 'V-3002', 'ORG-4001', 'ORG-4002', 'ORG-4003', 'AC-5001', 'AC-5002', 'AC-5003', 'AC-5005', 'L-105', 'L-109', 'L-110', 'L-112', 'EV-6001', 'EV-6002', 'EV-6003'], tags: ['smuggling', 'border', 'financial-layering'] },
  { id: 'C-2026-021', code: 'OP LANTERN', title: 'Structuring and escrow laundering through Baltic Shell', status: 'ACTIVE', priority: 'HIGH', leadInvestigatorId: 'U-2', openedAt: '2026-02-19', updatedAt: '2026-09-09', summary: 'Follow-the-money investigation into layered transfers between Ruritan Central, NordBank and Harbor Trust escrow accounts connected to Baltic Shell Holdings.', entityIds: ['P-1001', 'P-1004', 'P-1006', 'AC-5002', 'AC-5003', 'AC-5005', 'ORG-4003', 'L-106'], tags: ['money-laundering', 'escrow', 'structuring'] },
  { id: 'C-2026-033', code: 'OP IRONVEIL', title: 'Vehicle re-identification and clone plates', status: 'OPEN', priority: 'MEDIUM', leadInvestigatorId: 'U-3', openedAt: '2026-04-02', updatedAt: '2026-06-11', summary: 'Reyes Auto Exchange suspected of re-VINning vehicles used in corridor runs. Notary Elena Voss processed anomalous ownership transfers.', entityIds: ['P-1003', 'P-1008', 'V-3003', 'ORG-4004', 'L-103'], tags: ['vehicles', 'fraud'] },
  { id: 'C-2025-118', code: 'OP QUIETTIDE', title: 'Tip-driven safehouse verification', status: 'SUSPENDED', priority: 'LOW', leadInvestigatorId: 'U-1', openedAt: '2025-11-20', updatedAt: '2026-07-14', summary: 'Anonymous tip line reported recurring night meetings at 3 Albacore Close. Surveillance inconclusive; pending technical coverage.', entityIds: ['P-1001', 'L-112'], tags: ['tip', 'surveillance'] },
  { id: 'C-2026-040', code: 'OP CEDARWALL', title: 'Controlled delivery — Warehouse 14', status: 'ACTIVE', priority: 'CRITICAL', leadInvestigatorId: 'U-3', openedAt: '2026-08-29', updatedAt: '2026-09-10', summary: 'Joint operation with customs. Seized consignment replaced with inert substitute; Asante Haulage truck V-3001 delivered to Warehouse 14 on 6–7 Sep.', entityIds: ['P-1002', 'P-1005', 'P-1007', 'V-3001', 'L-105', 'EV-6002', 'PH-2002', 'PH-2005'], tags: ['controlled-delivery', 'joint-op'] },
];

export const events: IntelEvent[] = [
  { id: 'E-1001', caseId: 'C-2026-014', type: 'SIGHTING', title: 'Sarek vehicle near Pier 9', description: 'ANPR captured RUR 88-12 KA loitering at Meridian Freeport for 40 minutes.', occurredAt: '2026-08-16T14:22:00Z', severity: 'MEDIUM', locationId: 'L-109', entityIds: ['P-1001', 'V-3002'], source: 'ANPR' },
  { id: 'E-1002', caseId: 'C-2026-014', type: 'SEIZURE', title: 'Container XINU-884120-3 inspection', description: 'Contraband concealment layer found under floor panels. Manifest listed machine parts.', occurredAt: '2026-08-18T06:40:00Z', severity: 'HIGH', locationId: 'L-109', entityIds: ['P-1001', 'P-1002', 'ORG-4001', 'EV-6001'], source: 'Port Authority' },
  { id: 'E-1003', caseId: 'C-2026-014', type: 'TIP', title: 'Anonymous tip — Albacore Close meetings', description: 'Caller reported three late-night meetings at suspected safehouse over two weeks.', occurredAt: '2026-08-19T22:05:00Z', severity: 'LOW', locationId: 'L-112', entityIds: ['P-1001', 'L-112'], source: 'TIP' },
  { id: 'E-1004', caseId: 'C-2026-033', type: 'MEETING', title: 'Reyes–Voss notarization appointment', description: 'Ownership transfer for cargo van filed 45 minutes after corridor ANPR hit.', occurredAt: '2026-08-21T11:15:00Z', severity: 'MEDIUM', locationId: 'L-103', entityIds: ['P-1003', 'P-1008'], source: 'Registry' },
  { id: 'E-1005', caseId: 'C-2026-021', type: 'TRANSFER', title: 'Escrow payout #2 — Harbor Trust', description: 'EUR 84,000 released from AC-5005 to AC-5002 against invoice BSH-INV-2291 (consulting).', occurredAt: '2026-08-14T09:30:00Z', severity: 'HIGH', locationId: 'L-106', entityIds: ['P-1004', 'P-1006', 'AC-5005', 'AC-5002'], source: 'Bank Registry' },
  { id: 'E-1006', caseId: 'C-2026-021', type: 'SIGHTING', title: 'Petrova at Baltic Shell office', description: 'Tip-supported sighting; Petrova not employed by BSH. Pattern matches two prior visits.', occurredAt: '2026-08-22T16:40:00Z', severity: 'MEDIUM', locationId: 'L-106', entityIds: ['P-1004', 'ORG-4003'], source: 'TIP' },
  { id: 'E-1007', caseId: 'C-2026-014', type: 'TRAVEL', title: 'V-3001 at Kalm Pass — released in error', description: 'Truck flagged at border post; duty roster gap led to release. Driver log later falsified.', occurredAt: '2026-08-30T03:10:00Z', severity: 'CRITICAL', locationId: 'L-110', entityIds: ['P-1007', 'V-3001', 'EV-6003'], source: 'Border Registry' },
  { id: 'E-1008', caseId: 'C-2026-040', type: 'MEETING', title: 'Diallo–Asante call — 22 min', description: 'Call between PH-2002 and PH-2005 discussing "the Tuesday consignment" (voice intercept summary).', occurredAt: '2026-09-02T18:44:00Z', severity: 'HIGH', entityIds: ['P-1002', 'P-1007'], source: 'CDR' },
  { id: 'E-1009', caseId: 'C-2026-040', type: 'SIGHTING', title: 'V-3001 entered Dockside Industrial Zone', description: 'ANPR chain tracked truck from depot to Dockside; matched witness description at Warehouse 14.', occurredAt: '2026-09-06T20:12:00Z', severity: 'HIGH', locationId: 'L-105', entityIds: ['P-1007', 'V-3001'], source: 'ANPR' },
  { id: 'E-1010', caseId: 'C-2026-040', type: 'BREACH', title: 'Odeyemi approached by unknown male', description: 'Warehouse supervisor Samuel Odeyemi questioned by unidentified man about "new stock". Odeyemi is cooperating witness.', occurredAt: '2026-09-07T12:05:00Z', severity: 'CRITICAL', locationId: 'L-105', entityIds: ['P-1005'], source: 'Field Report' },
  { id: 'E-1011', caseId: 'C-2026-040', type: 'SIGHTING', title: 'Controlled delivery — drop completed', description: 'Truck V-3001 unloaded at Warehouse 14, 21:15. Surveillance maintained; no arrests yet.', occurredAt: '2026-09-07T21:15:00Z', severity: 'HIGH', locationId: 'L-105', entityIds: ['P-1002', 'P-1007', 'V-3001', 'EV-6002'], source: 'Field Report' },
  { id: 'E-1012', caseId: 'C-2025-118', type: 'TIP', title: 'Follow-up tip — safehouse still active', description: 'Second anonymous call corroborated meeting pattern at 3 Albacore Close.', occurredAt: '2026-09-01T23:40:00Z', severity: 'LOW', locationId: 'L-112', entityIds: ['P-1001'], source: 'TIP' },
  { id: 'E-1013', caseId: 'C-2026-014', type: 'CALL', title: 'Burst pattern: 14 calls in 90 minutes', description: 'PH-2001 contacted PH-2002, PH-2004 and an unidentified burner in rapid succession after news of inspection leaked.', occurredAt: '2026-08-18T15:02:00Z', severity: 'HIGH', entityIds: ['P-1001', 'P-1002', 'P-1004'], source: 'CDR' },
  { id: 'E-1014', caseId: 'C-2026-021', type: 'TRANSFER', title: 'Structuring: 6 sub-threshold deposits', description: 'Six cash deposits just below reporting threshold into AC-5002 across two days, three branches.', occurredAt: '2026-09-03T10:20:00Z', severity: 'HIGH', entityIds: ['P-1004', 'AC-5002'], source: 'Bank Registry' },
  { id: 'E-1015', caseId: 'C-2026-014', type: 'MEETING', title: 'Sarek–Lindqvist meeting, Harbor Ring', description: 'Physical surveillance observed 40-minute meeting at Baltic Shell office lobby.', occurredAt: '2026-09-05T13:25:00Z', severity: 'MEDIUM', locationId: 'L-106', entityIds: ['P-1001', 'P-1006'], source: 'Field Report' },
];

export const transactions: Transaction[] = [
  { id: 'TX-9001', accountId: 'AC-5003', counterpartyAccountId: 'AC-5002', counterpartyLabel: 'NordBank ****3348', occurredAt: '2026-03-12T10:00:00Z', amount: 42000, currency: 'EUR', direction: 'OUT', channel: 'WIRE', narrative: 'Consulting retainer — Baltic advisory', riskFlags: [] },
  { id: 'TX-9002', accountId: 'AC-5003', counterpartyAccountId: 'AC-5002', counterpartyLabel: 'NordBank ****3348', occurredAt: '2026-04-08T10:00:00Z', amount: 38000, currency: 'EUR', direction: 'OUT', channel: 'WIRE', narrative: 'Consulting retainer — Baltic advisory', riskFlags: [] },
  { id: 'TX-9003', accountId: 'AC-5002', occurredAt: '2026-04-19T14:30:00Z', amount: 9500, currency: 'EUR', direction: 'IN', channel: 'CASH', narrative: 'Branch deposit — NordBank City Center', riskFlags: ['JUST-BELOW-THRESHOLD'] },
  { id: 'TX-9004', accountId: 'AC-5002', occurredAt: '2026-04-19T16:05:00Z', amount: 9400, currency: 'EUR', direction: 'IN', channel: 'CASH', narrative: 'Branch deposit — NordBank Northgate', riskFlags: ['JUST-BELOW-THRESHOLD', 'MULTI-BRANCH'] },
  { id: 'TX-9005', accountId: 'AC-5002', occurredAt: '2026-04-20T11:20:00Z', amount: 9800, currency: 'EUR', direction: 'IN', channel: 'CASH', narrative: 'Branch deposit — NordBank Harborfront', riskFlags: ['JUST-BELOW-THRESHOLD', 'MULTI-BRANCH'] },
  { id: 'TX-9006', accountId: 'AC-5005', counterpartyAccountId: 'AC-5002', counterpartyLabel: 'NordBank ****3348', occurredAt: '2026-06-22T09:00:00Z', amount: 61500, currency: 'EUR', direction: 'OUT', channel: 'WIRE', narrative: 'Escrow release — invoice BSH-INV-1877', riskFlags: ['ESCROW-RELEASE'] },
  { id: 'TX-9007', accountId: 'AC-5005', counterpartyAccountId: 'AC-5002', counterpartyLabel: 'NordBank ****3348', occurredAt: '2026-08-14T09:30:00Z', amount: 84000, currency: 'EUR', direction: 'OUT', channel: 'WIRE', narrative: 'Escrow release — invoice BSH-INV-2291 (consulting)', riskFlags: ['ESCROW-RELEASE', 'ROUND-AMOUNT'] },
  { id: 'TX-9008', accountId: 'AC-5001', counterpartyAccountId: 'AC-5005', counterpartyLabel: 'Harbor Trust ****0817', occurredAt: '2026-05-10T13:15:00Z', amount: 51200, currency: 'USD', direction: 'OUT', channel: 'WIRE', narrative: 'Freight invoice chain — MTF to BSH', riskFlags: ['INVOICE-CHAIN'] },
  { id: 'TX-9009', accountId: 'AC-5001', counterpartyAccountId: 'AC-5005', counterpartyLabel: 'Harbor Trust ****0817', occurredAt: '2026-08-30T15:45:00Z', amount: 47800, currency: 'USD', direction: 'OUT', channel: 'WIRE', narrative: 'Freight invoice chain — MTF to BSH', riskFlags: ['INVOICE-CHAIN'] },
  { id: 'TX-9010', accountId: 'AC-5001', counterpartyLabel: 'Cash withdrawal', occurredAt: '2026-09-05T08:10:00Z', amount: 22000, currency: 'USD', direction: 'OUT', channel: 'CASH', narrative: 'Counter withdrawal — Freeport branch', riskFlags: ['LARGE-CASH'] },
  { id: 'TX-9011', accountId: 'AC-5004', counterpartyLabel: 'Mobile transfer — +250 788 412 091', occurredAt: '2026-09-06T19:55:00Z', amount: 1800, currency: 'USD', direction: 'OUT', channel: 'MOBILE', narrative: 'Wallet transfer two hours before dockside delivery', riskFlags: ['TIMED-TO-EVENT', 'UNREGISTERED-COUNTERPARTY'] },
  { id: 'TX-9012', accountId: 'AC-5004', occurredAt: '2026-09-07T07:30:00Z', amount: 1200, currency: 'USD', direction: 'IN', channel: 'MOBILE', narrative: 'Inbound wallet top-up', riskFlags: [] },
  { id: 'TX-9013', accountId: 'AC-5003', counterpartyAccountId: 'AC-5001', counterpartyLabel: 'Coastal Union ****7712', occurredAt: '2026-07-19T10:00:00Z', amount: 28900, currency: 'USD', direction: 'OUT', channel: 'WIRE', narrative: 'Advance freight payment', riskFlags: [] },
  { id: 'TX-9014', accountId: 'AC-5002', occurredAt: '2026-09-03T10:20:00Z', amount: 9200, currency: 'EUR', direction: 'IN', channel: 'CASH', narrative: 'Branch deposit — NordBank City Center', riskFlags: ['JUST-BELOW-THRESHOLD'] },
  { id: 'TX-9015', accountId: 'AC-5002', occurredAt: '2026-09-03T13:40:00Z', amount: 9700, currency: 'EUR', direction: 'IN', channel: 'CASH', narrative: 'Branch deposit — NordBank Northgate', riskFlags: ['JUST-BELOW-THRESHOLD', 'MULTI-BRANCH'] },
  { id: 'TX-9016', accountId: 'AC-5002', occurredAt: '2026-09-04T09:05:00Z', amount: 9900, currency: 'EUR', direction: 'IN', channel: 'CASH', narrative: 'Branch deposit — NordBank Harborfront', riskFlags: ['JUST-BELOW-THRESHOLD', 'MULTI-BRANCH'] },
  { id: 'TX-9017', accountId: 'AC-5001', counterpartyLabel: 'Port services — Meridian Freeport', occurredAt: '2026-08-12T11:00:00Z', amount: 7300, currency: 'USD', direction: 'OUT', channel: 'CHECK', narrative: 'Pier 9 handling fees', riskFlags: [] },
  { id: 'TX-9018', accountId: 'AC-5005', counterpartyAccountId: 'AC-5001', counterpartyLabel: 'Coastal Union ****7712', occurredAt: '2026-06-30T16:20:00Z', amount: 15400, currency: 'USD', direction: 'OUT', channel: 'WIRE', narrative: 'Refund against cancelled invoice BSH-INV-1902', riskFlags: ['ROUND-AMOUNT', 'INVOICE-CHAIN'] },
];

export const cdrRecords: CDRRecord[] = (() => {
  const pairs: Array<[string, string, number]> = [
    ['+250 788 412 091', '+250 733 908 554', 34],
    ['+250 788 412 091', '+31 6 4420 8917', 12],
    ['+250 733 908 554', '+250 790 556 710', 21],
    ['+46 70 552 0138', '+31 6 4420 8917', 8],
    ['+250 790 556 710', '+250 725 110 332', 5],
    ['+250 788 412 091', 'UNKNOWN-BURNER-7', 3],
  ];
  const out: CDRRecord[] = [];
  let n = 0;
  for (const [a, b, count] of pairs) {
    for (let i = 0; i < count; i++) {
      n += 1;
      const d = new Date(Date.UTC(2026, 7, 1 + (i % 27), 6 + ((i * 7) % 16), (i * 13) % 60));
      out.push({
        id: `CDR-${String(n).padStart(4, '0')}`,
        callerNumber: a, calleeNumber: b, startedAt: d.toISOString(),
        durationSec: i % 4 === 0 ? 0 : 45 + ((i * 97) % 840),
        kind: i % 4 === 0 ? 'SMS' : 'VOICE',
        cellSiteId: 'L-111', cellSiteName: 'Cell site KIV-114',
        imei: a === '+250 788 412 091' ? '352099004477213' : undefined,
      });
    }
  }
  return out;
})();

export const alerts: Alert[] = [
  { id: 'AL-01', severity: 'CRITICAL', rule: 'STRUCT-006', title: 'Structured deposits below reporting threshold', description: 'Six cash deposits between EUR 9,200–9,900 into AC-5002 across three branches in 48 hours.', createdAt: '2026-09-04T09:20:00Z', status: 'NEW', entityIds: ['P-1004', 'AC-5002'], caseId: 'C-2026-021' },
  { id: 'AL-02', severity: 'CRITICAL', rule: 'CDR-BURST-002', title: 'Post-event call burst', description: '14 calls in 90 minutes from PH-2001 following the Pier 9 inspection, including one unidentified burner.', createdAt: '2026-08-18T15:30:00Z', status: 'ACKNOWLEDGED', entityIds: ['P-1001', 'PH-2001'], caseId: 'C-2026-014' },
  { id: 'AL-03', severity: 'HIGH', rule: 'FIN-ESCROW-011', title: 'Round-amount escrow releases', description: 'Two round-amount payouts (EUR 61,500 / 84,000) from Harbor Trust escrow AC-5005 to AC-5002 against generic consulting invoices.', createdAt: '2026-08-14T10:00:00Z', status: 'INVESTIGATING', entityIds: ['P-1004', 'P-1006', 'AC-5005'], caseId: 'C-2026-021' },
  { id: 'AL-04', severity: 'HIGH', rule: 'ANPR-GEO-014', title: 'Vehicle near active operation zone', description: 'V-3001 (Asante Haulage) entered Dockside Industrial Zone during controlled delivery window.', createdAt: '2026-09-06T20:30:00Z', status: 'NEW', entityIds: ['P-1007', 'V-3001', 'L-105'], caseId: 'C-2026-040' },
  { id: 'AL-05', severity: 'HIGH', rule: 'NET-CENT-003', title: 'High-centrality node detected', description: 'Entity PH-2002 has the highest betweenness in the current case graph — recommended priority target for interception.', createdAt: '2026-09-08T07:00:00Z', status: 'NEW', entityIds: ['P-1002', 'PH-2002'], caseId: 'C-2026-014' },
  { id: 'AL-06', severity: 'MEDIUM', rule: 'TIP-CORR-021', title: 'Corroborated tip pattern', description: 'Two independent tips referencing activity at L-112 (3 Albacore Close) within 14 days.', createdAt: '2026-09-02T00:10:00Z', status: 'ACKNOWLEDGED', entityIds: ['P-1001', 'L-112'], caseId: 'C-2025-118' },
  { id: 'AL-07', severity: 'MEDIUM', rule: 'CDR-IMEI-008', title: 'SIM swap / IMEI churn', description: 'PH-2004 IMEI changed twice in 30 days while IMSI remained stable — possible handset rotation.', createdAt: '2026-08-29T11:00:00Z', status: 'RESOLVED', entityIds: ['P-1004', 'PH-2004'], caseId: 'C-2026-021' },
  { id: 'AL-08', severity: 'LOW', rule: 'REG-TIMING-017', title: 'Notarization shortly after ANPR hit', description: 'Vehicle ownership transfer notarized 45 minutes after corridor ANPR alert.', createdAt: '2026-08-21T12:00:00Z', status: 'RESOLVED', entityIds: ['P-1003', 'P-1008'], caseId: 'C-2026-033' },
];

export const dataSources: DataSource[] = [
  { id: 'DS-1', name: 'National CDR Gateway', kind: 'CDR', status: 'CONNECTED', lastSync: '2026-09-10T06:00:00Z', recordsIngested: 1284410, owner: 'Telecom Liaison Unit' },
  { id: 'DS-2', name: 'Banking & FIU Registry', kind: 'FINANCIAL', status: 'CONNECTED', lastSync: '2026-09-09T23:30:00Z', recordsIngested: 384120, owner: 'FIU Desk' },
  { id: 'DS-3', name: 'ANPR Corridor Network', kind: 'ANPR', status: 'DEGRADED', lastSync: '2026-09-08T14:10:00Z', recordsIngested: 902144, owner: 'Highway Patrol' },
  { id: 'DS-4', name: 'Anonymous Tip Line', kind: 'TIP', status: 'CONNECTED', lastSync: '2026-09-10T05:45:00Z', recordsIngested: 12308, owner: 'Intake Desk' },
  { id: 'DS-5', name: 'Corporate & Vehicle Registry', kind: 'REGISTRY', status: 'CONNECTED', lastSync: '2026-09-07T09:00:00Z', recordsIngested: 2210470, owner: 'Records Division' },
  { id: 'DS-6', name: 'Open Source Monitoring', kind: 'OPEN_SOURCE', status: 'OFFLINE', lastSync: '2026-08-27T18:00:00Z', recordsIngested: 54031, owner: 'OSINT Cell' },
];

export const entityById = new Map<string, Entity>(entities.map((e) => [e.id, e]));
export const locationById = new Map<string, LocationRecord>(locations.map((l) => [l.id, l]));