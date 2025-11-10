export default function ResolverCoverage({authority, publicResolvers}:{authority?: string[]; publicResolvers?: string[]}) {
  const hasAuthority = !!authority && authority.length>0;
  const hasPublic = !!publicResolvers && publicResolvers.length>0;
  if (!hasAuthority && !hasPublic) return null;

  return (
    <div>
      <p className="form-hint">Public resolvers use cached answers; authoritative entries come directly from the zone’s nameservers.</p>
      <div className="coverage-chips">
        {hasAuthority && authority!.map((ns,i)=>(
          <span key={`auth-${ns}-${i}`} className="coverage-chip" title="Authoritative nameserver (non-recursive)">
            <span className="coverage-icon" aria-hidden="true">A</span>
            {ns}
          </span>
        ))}
        {hasPublic && publicResolvers!.map((resolver,i)=>(
          <span key={`pub-${resolver}-${i}`} className="coverage-chip" title="Public recursive resolver">
            <span className="coverage-icon" aria-hidden="true">G</span>
            {resolver}
          </span>
        ))}
      </div>
    </div>
  );
}
