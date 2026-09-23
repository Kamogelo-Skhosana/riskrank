"""FastAPI routes for the riskrank dashboard.

Tickets: R035, R036, R037, R038
"""

from fastapi import FastAPI

app = FastAPI(title="riskrank dashboard")


@app.get("/scans")
def list_scans():
    """List all past scans.

    TODO (R036): query the scans table, return summary rows
    (id, target_url, date, top_priority).
    """
    raise NotImplementedError


@app.get("/scans/{scan_id}")
def get_scan(scan_id: int):
    """Get full findings detail for one scan.

    TODO (R037): query findings for scan_id, return ranked list.
    """
    raise NotImplementedError


@app.get("/scans/trend")
def get_trend():
    """Get aggregated risk-over-time data across all scans.

    TODO (R038): aggregate scores per scan date for a trend chart.
    """
    raise NotImplementedError
