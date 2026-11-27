export type EntityType = string;
export type EntityStatus = string;
export type Severity = string;
export type AlertSeverity = string;
export type AlertStatus = string;
export type CaseStatus = string;
export type Priority = string;
export type RelationshipType = string;
export type EventType = string;
export interface InvestigatorProfile { id:string; name:string; email:string; badge:string; unit:string; role:string; phone:string; [key:string]:any }
export interface AuthSession { token:string; investigator?:InvestigatorProfile; profile?:InvestigatorProfile; expiresAt?:string; [key:string]:any }
export interface Entity { id:string; type:EntityType; label:string; subtype?:string; status:string; riskScore:number; aliases:string[]; attributes:Record<string, any>; createdAt:string; updatedAt:string; [key:string]:any }
export interface Relationship { id:string; sourceId:string; targetId:string; source?:string; target?:string; type:string; confidence?:any; strength:number; firstSeen?:string; lastSeen?:string; label?:string; attributes?:Record<string, any>; [key:string]:any }
export interface IntelEvent { id:string; type:string; title:string; description:string; occurredAt:string; entityIds?:string[]; caseId?:string; severity?:string; locationId?:string; source?:string; [key:string]:any }
export interface LocationRecord { id:string; name:string; address?:string; city?:string; country?:string; lat:number; lng:number; riskScore?:number; entityIds?:string[]; type?:string; notes?:string; [key:string]:any }
export interface Transaction { id:string; accountId:string; counterpartyAccountId?:string; counterpartyLabel?:string; occurredAt:string; amount:number; currency:string; direction:'IN'|'OUT'; channel:string; narrative?:string; riskFlags:string[]; [key:string]:any }
export interface CDRRecord { id:string; callerNumber:string; calleeNumber:string; startedAt:string; durationSec:number; kind:string; cellSiteId?:string; cellSiteName?:string; imei?:string; [key:string]:any }
export interface Alert { id:string; severity:string; rule:string; title:string; description:string; createdAt:string; status:string; entityIds:string[]; caseId?:string; [key:string]:any }
export interface DataSource { id:string; name:string; kind:string; status:string; lastSync:string; recordsIngested:number; owner:string; [key:string]:any }
export interface Case { id:string; code:string; title:string; description?:string; summary?:string; status:string; priority:string; leadInvestigatorId?:string; createdAt?:string; updatedAt?:string; openedAt?:string; entityIds:string[]; tags:string[]; [key:string]:any }
export interface InvestigationReport { id:string; caseId:string; title:string; generatedAt:string; authorId?:string; status:string; summary:string; [key:string]:any }
export interface NetworkView { centerId:string; nodes:Entity[]; edges:Relationship[]; [key:string]:any }
