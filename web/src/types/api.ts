export class ApiError extends Error { status:number; constructor(status:number,message:string){super(message);this.name='ApiError';this.status=status;} }
export interface EntityQuery { q?:any; type?:any; riskMin?:any; page?:any; pageSize?:any; [key:string]:any }
export interface CaseQuery { q?:any; status?:any; priority?:any; page?:any; pageSize?:any; [key:string]:any }
export interface RelationshipQuery { entityId?:any; type?:any; page?:any; pageSize?:any; [key:string]:any }
export interface EventQuery { entityId?:any; caseId?:any; type?:any; severity?:any; from?:any; to?:any; page?:any; pageSize?:any; [key:string]:any }
export interface LocationQuery { q?:any; page?:any; pageSize?:any; type?:any; [key:string]:any }
export interface TransactionQuery { accountId?:any; page?:any; pageSize?:any; channel?:any; direction?:any; minAmount?:any; from?:any; to?:any; [key:string]:any }
export interface CDRQuery { caller?:any; callee?:any; page?:any; pageSize?:any; number?:any; kind?:any; from?:any; to?:any; [key:string]:any }
export interface AlertQuery { severity?:any; status?:any; page?:any; pageSize?:any; [key:string]:any }
