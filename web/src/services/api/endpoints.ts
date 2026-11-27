import type { Page } from '../../types/api-shim';
import type { Alert, Case, CDRRecord, DataSource, Entity, IntelEvent, LocationRecord, Relationship, Transaction, AuthSession, InvestigationReport, NetworkView, InvestigatorProfile } from '../../types/models';
import type { AlertQuery, CaseQuery, CDRQuery, EntityQuery, EventQuery, LocationQuery, RelationshipQuery, TransactionQuery } from '../../types/api';
export interface LoginCredentials { email:string; password:string }
export interface DashboardData { activeCases:number; entitiesAnalyzed:number; highRiskConnections:number; suspiciousPatterns:number; openAlerts:Alert[]; recentAlerts?:Alert[]; recentCases:Case[]; recentEvents:IntelEvent[]; stats?:Record<string,number>; [key:string]:any }
export interface ApiAdapter {
 login(c:LoginCredentials):Promise<AuthSession>; profile():Promise<InvestigatorProfile>; dashboard():Promise<DashboardData>;
 listCases(q?:CaseQuery):Promise<Page<Case>>; getCase(id:string):Promise<Case>; listEntities(q?:EntityQuery):Promise<Page<Entity>>; getEntity(id:string):Promise<Entity>; search(q:string):Promise<any>;
 getNetwork(id:string,opts?:{depth?:1|2;types?:string[]}):Promise<NetworkView>; listRelationships(q?:RelationshipQuery):Promise<Page<Relationship>>; listEvents(q?:EventQuery):Promise<Page<IntelEvent>>; listLocations(q?:LocationQuery):Promise<Page<LocationRecord>>; listTransactions(q?:TransactionQuery):Promise<Page<Transaction>>; listCDR(q?:CDRQuery):Promise<Page<CDRRecord>>; listAlerts(q?:AlertQuery):Promise<Page<Alert>>; acknowledgeAlert(id:string):Promise<any>; generateReport(caseId:string):Promise<any>; listDataSources():Promise<DataSource[]>; importData(sourceId:string,payload:any):Promise<any>;
}
