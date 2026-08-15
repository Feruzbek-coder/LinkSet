import type {ReactNode} from "react";
import {CheckCircle2,CircleHelp,ShieldCheck,TriangleAlert} from "lucide-react";

export function Ring({value,label,color="blue"}:{value:number;label:string;color?:"blue"|"green"}){return <div className={`ring ${color}`} style={{"--value":`${value*3.6}deg`} as React.CSSProperties}><div><strong>{Math.round(value)}</strong><span>{label}</span></div></div>}
export function Metric({icon,title,value,detail,tone="blue"}:{icon:ReactNode;title:string;value:string;detail:string;tone?:string}){return <div className="metric card"><div className={`metric-icon ${tone}`}>{icon}</div><div><span>{title}</span><strong>{value}</strong><small>{detail}</small></div></div>}
export function StatusRow({label,ok,detail}:{label:string;ok?:boolean;detail:string}){const known=typeof ok==="boolean";return <div className="status-row"><div className={known?(ok?"status good":"status bad"):"status unknown"}>{known?(ok?<CheckCircle2 size={17}/>:<TriangleAlert size={17}/>):<CircleHelp size={17}/>}</div><div><b>{label}</b><span>{detail}</span></div></div>}
export function Empty({title,children}:{title:string;children:ReactNode}){return <div className="empty"><ShieldCheck size={36}/><h3>{title}</h3><p>{children}</p></div>}
export function Skeleton(){return <div className="skeleton-page"><div/><div className="skeleton-grid"><i/><i/><i/><i/></div><div className="skeleton-large"/></div>}
