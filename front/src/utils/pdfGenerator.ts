import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';

interface ScanData {
    target: string;
    risk_summary: {
        total_hosts: number;
        vulnerable_services: number;
        critical_paths: number;
        total_bounty: number;
    };
    graph: {
        nodes: any[];
        edges: any[];
    };
    suggestions: any[];
}

export const generateProfessionalPDF = (scan: ScanData, lang: string) => {
    const doc = new jsPDF();
    const isEn = lang === 'en';
    const now = new Date().toLocaleString();

    // -- Header --
    doc.setFillColor(15, 23, 42); // slate-950
    doc.rect(0, 0, 210, 40, 'F');

    doc.setTextColor(255, 255, 255);
    doc.setFontSize(22);
    doc.setFont('helvetica', 'bold');
    doc.text('PATH2ROOT', 14, 25);

    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    const subtitle = isEn ? 'OPERATIONAL SECURITY AUDIT REPORT' : 'RAPPORT D\'AUDIT DE SÉCURITÉ OPÉRATIONNELLE';
    doc.text(subtitle, 14, 32);

    doc.setFontSize(8);
    doc.text(`${isEn ? 'Date' : 'Date'}: ${now}`, 160, 25);
    doc.text(`${isEn ? 'Target' : 'Cible'}: ${scan.target}`, 160, 30);

    // -- Executive Summary --
    let y = 55;
    doc.setTextColor(15, 23, 42);
    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    doc.text(isEn ? '1. EXECUTIVE SUMMARY' : '1. RÉSUMÉ EXÉCUTIF', 14, y);

    y += 10;
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    const summaryText = isEn
        ? `The security audit of ${scan.target} revealed ${scan.risk_summary.vulnerable_services} vulnerable services across ${scan.risk_summary.total_hosts} hosts. Total identified bounty value stands at $${scan.risk_summary.total_bounty.toLocaleString()}.`
        : `L'audit de sécurité de ${scan.target} a révélé ${scan.risk_summary.vulnerable_services} services vulnérables sur ${scan.risk_summary.total_hosts} hôtes. La valeur totale des primes identifiées s'élève à ${scan.risk_summary.total_bounty.toLocaleString()}$.`;

    const splitText = doc.splitTextToSize(summaryText, 180);
    doc.text(splitText, 14, y);
    y += (splitText.length * 5) + 10;

    // -- Metrics Table --
    autoTable(doc, {
        startY: y,
        head: [[isEn ? 'Metric' : 'Métrique', isEn ? 'Value' : 'Valeur']],
        body: [
            [isEn ? 'Total Hosts Discovered' : 'Total Hôtes Découverts', scan.risk_summary.total_hosts],
            [isEn ? 'Vulnerable Services' : 'Services Vulnérables', scan.risk_summary.vulnerable_services],
            [isEn ? 'Critical Attack Paths' : 'Chemins d\'Attaque Critiques', scan.risk_summary.critical_paths],
            [isEn ? 'Estimated Bounty Value' : 'Valeur Estimée des Primes', `$${scan.risk_summary.total_bounty.toLocaleString()}`],
        ],
        theme: 'striped',
        headStyles: { fillColor: [99, 102, 241] }, // indigo-500
    });

    y = (doc as any).lastAutoTable.finalY + 20;

    // -- Technical Findings --
    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    doc.text(isEn ? '2. TECHNICAL FINDINGS' : '2. CONSTATATIONS TECHNIQUES', 14, y);

    y += 10;
    const vulnData = scan.graph.nodes
        .filter(n => n.properties.status === 'vulnerable' || n.properties.is_critical === 'true')
        .map(n => [
            n.label,
            n.id,
            n.properties.is_critical === 'true' ? (isEn ? 'CRITICAL' : 'CRITIQUE') : (isEn ? 'High' : 'Élevé'),
            n.properties.type || n.node_type
        ]);

    autoTable(doc, {
        startY: y,
        head: [[isEn ? 'Asset' : 'Actif', 'ID/IP', 'Risk', 'Type']],
        body: vulnData,
        theme: 'grid',
        headStyles: { fillColor: [239, 68, 68] }, // red-500
        columnStyles: {
            2: { fontStyle: 'bold' }
        }
    });

    // -- Remediation Plan --
    doc.addPage();
    y = 20;
    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    doc.text(isEn ? '3. REMEDIATION STRATEGY' : '3. STRATÉGIE DE REMÉDIATION', 14, y);

    y += 10;
    const remediationData = scan.suggestions.map(s => [
        s.label,
        s.node_id,
        s.impact === 'High' ? (isEn ? 'Priority 1' : 'Priorité 1') : (isEn ? 'Standard' : 'Standard')
    ]);

    autoTable(doc, {
        startY: y,
        head: [[isEn ? 'Fix Required' : 'Correction Requise', isEn ? 'Affected Node' : 'Nœud Affecté', 'Priority']],
        body: remediationData,
        theme: 'striped',
        headStyles: { fillColor: [34, 197, 94] }, // green-500
    });

    // -- Footer (Page Numbers) --
    const pageCount = (doc as any).internal.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
        doc.setPage(i);
        doc.setFontSize(8);
        doc.setTextColor(150);
        doc.text(`Page ${i} / ${pageCount}`, 190, 285);
        doc.text('Path2Root Strategic Intel System', 14, 285);
    }

    doc.save(`Path2Root_Report_${scan.target.replace(/[^a-z0-9]/gi, '_')}.pdf`);
};

export const generateHackerOnePDF = (scan: ScanData, lang: string) => {
    const doc = new jsPDF();
    const isEn = lang === 'en';
    const now = new Date().toLocaleString();

    // -- Header HackerOne Style --
    doc.setFillColor(62, 72, 82); // HackerOne Dark Grey
    doc.rect(0, 0, 210, 30, 'F');

    doc.setTextColor(255, 255, 255);
    doc.setFontSize(18);
    doc.setFont('helvetica', 'bold');
    doc.text('HackerOne Report', 14, 20);

    doc.setFontSize(10);
    doc.text(`#${Math.floor(Math.random() * 100000)}`, 180, 20); // Fake Report ID

    // -- Title --
    let y = 50;
    doc.setTextColor(23, 23, 23);
    doc.setFontSize(24);
    doc.text(isEn ? `Security Assessment: ${scan.target}` : `Audit de Sécurité: ${scan.target}`, 14, y);

    y += 15;
    doc.setFontSize(12);
    doc.setTextColor(100);
    doc.text(`Submitted by: Path2Root Automated Scanner`, 14, y);
    doc.text(`Date: ${now}`, 14, y + 6);

    // -- Summary Box --
    y += 20;
    doc.setFillColor(245, 247, 250); // Light gray bg
    doc.setDrawColor(200);
    doc.rect(14, y, 180, 40, 'FD');

    doc.setFontSize(14);
    doc.setTextColor(50);
    doc.text(isEn ? 'Vulnerability Summary' : 'Résumé des Vulnérabilités', 20, y + 10);

    doc.setFontSize(11);
    doc.text(`Critical: ${scan.risk_summary.critical_paths > 0 ? scan.risk_summary.critical_paths : '0'}`, 20, y + 25);
    doc.text(`High: ${scan.risk_summary.vulnerable_services}`, 60, y + 25);
    doc.text(`Bounty: $${scan.risk_summary.total_bounty.toLocaleString()}`, 100, y + 25);

    // -- Vulnerabilities Table --
    y += 50;
    const vulnData = scan.graph.nodes
        .filter(n => n.properties.status === 'vulnerable' || n.properties.is_critical === 'true')
        .map(n => [
            n.label,
            n.properties.is_critical === 'true' ? 'Critical' : 'High',
            n.properties.cvss || 'N/A',
            n.properties.finding || 'Unknown Issue'
        ]);

    autoTable(doc, {
        startY: y,
        head: [[isEn ? 'Asset' : 'Actif', 'Severity', 'CVSS', 'Description']],
        body: vulnData,
        theme: 'plain',
        headStyles: { fillColor: [62, 72, 82], textColor: 255 },
        styles: { cellPadding: 5, fontSize: 10 },
        columnStyles: { 1: { fontStyle: 'bold', textColor: [220, 38, 38] } }
    });

    doc.save(`H1_Report_${scan.target.replace(/[^a-z0-9]/gi, '_')}.pdf`);
};
