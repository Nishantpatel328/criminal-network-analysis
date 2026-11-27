import { useCallback, useEffect, useState } from 'react';
export function useAsync<T>(fn:()=>Promise<T>, deps:any[]){
 const [state,setState]=useState<{data:T|undefined;loading:boolean;error:any}>({data:undefined,loading:true,error:undefined});
 const run=useCallback(()=>{let active=true;setState(s=>({...s,loading:true,error:undefined}));return fn().then(data=>{if(active)setState({data,loading:false,error:undefined});return data}).catch(error=>{if(active)setState({data:undefined,loading:false,error});throw error}).finally(()=>{active=false})},deps);
 useEffect(()=>{let active=true;setState(s=>({...s,loading:true,error:undefined}));fn().then(data=>active&&setState({data,loading:false,error:undefined})).catch(error=>active&&setState({data:undefined,loading:false,error}));return()=>{active=false}},deps);
 return {...state,reload:()=>run()};
}
