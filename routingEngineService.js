import db from '../db/index.js';

/**
 * Route incoming report to the appropriate department and field officer based on category & ward jurisdiction.
 * Attaches organization_id to report so Resource.organization_id == Subject.organization_id works in ABAC checks.
 */
export function routeReport(report) {
    const category = (report.category || 'other').toLowerCase();
    const wardName = report.ward_name || report.address || 'Ward 12';

    const orgs = db.prepare('SELECT * FROM organizations').all();
    let matchedOrg = orgs.find(o => {
        const wards = JSON.parse(o.jurisdiction_wards || '[]');
        return wards.some(w => wardName.toLowerCase().includes(w.toLowerCase()));
    });

    if (!matchedOrg) {
        matchedOrg = orgs[0] || {
            organization_id: 'dept_sanitation_01',
            name: 'Sanitation & Solid Waste Management',
            code: 'SWM_NAGPUR'
        };
    }

    const defaultOfficer = {
        id: 'usr_superadmin_001',
        name: 'Chief Inspector R. Sharma',
        email: 'sharma@nagpurmc.gov.in'
    };

    const updatedReport = {
        ...report,
        ward_name: wardName,
        organization_id: matchedOrg.organization_id,
        assigned_department_id: matchedOrg.organization_id,
        assigned_department_name: matchedOrg.name,
        assigned_officer_id: defaultOfficer.id,
        assigned_officer_name: defaultOfficer.name,
        status: 'ASSIGNED',
        assigned_at: new Date().toISOString()
    };

    console.log(`[ROUTING ENGINE] Report ${report.id} (${category} in ${wardName}) ➔ Assigned to ${matchedOrg.name} (Org ID: ${matchedOrg.organization_id})`);
    dispatchWebhookEvent('report.assigned', updatedReport);

    return updatedReport;
}

export function dispatchWebhookEvent(eventType, reportData) {
    const webhookPayload = {
        event: eventType,
        timestamp: new Date().toISOString(),
        report_id: reportData.id || reportData.report_id,
        location_id: reportData.location_id,
        ward_name: reportData.ward_name,
        status: reportData.status,
        organization_id: reportData.organization_id,
        department: reportData.assigned_department_name
    };

    console.log(`[WEBHOOK DISPATCH] Event: ${eventType} | Target: NGO/Municipal Push Dispatch | Payload:`, webhookPayload);
}
