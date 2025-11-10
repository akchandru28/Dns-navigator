export default function SummaryPills({passC, warnC, failC}:{passC:number, warnC:number, failC:number}) {
  return (
    <div className="pills">
      <span className="pill pill--pass">PASS {passC}</span>
      <span className="pill pill--warn">WARN {warnC}</span>
      <span className="pill pill--fail">FAIL {failC}</span>
    </div>
  );
}
