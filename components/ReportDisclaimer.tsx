/**
 * Report view disclaimer and footer. Use at top and bottom of every benchmark report page.
 */

export function ReportDisclaimer() {
  return (
    <div className="rounded-lg border border-amber-700/50 bg-amber-900/20 p-4 text-left">
      <h3 className="font-semibold text-amber-200 text-sm">Automated data only</h3>
      <p className="text-slate-400 text-xs mt-1">
        This report aggregates publicly available pricing data from official websites,
        the Wayback Machine, and public sector contracts. It has not been audited or
        verified by humans. Verify all figures independently before use.
      </p>
    </div>
  );
}

export function ReportFooter({ reportId }: { reportId?: string }) {
  return (
    <footer className="text-xs text-slate-500 mt-8 border-t border-slate-700 pt-4">
      <p>
        Generated: {new Date().toISOString().slice(0, 10)} | Sources: Public
        pricing pages, Archive.org, Contracts Finder
      </p>
      <p className="mt-1">
        <a href="/report-error" className="text-purple-400 hover:underline">
          Report error
        </a>
        {reportId && (
          <>
            {" "}
            | Access expires in 30 days | Last updated: dynamic
          </>
        )}
      </p>
      <p className="mt-2 text-slate-600">
        AUTOMATED DATA AGGREGATION — FOR INFORMATIONAL USE ONLY. Not audited.
        Not verified. Not professional advice. Verify independently before use.
      </p>
    </footer>
  );
}
