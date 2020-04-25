export interface Resolve {
    id: number;
    path: string;
    dev: boolean;
    optional: boolean;
    bundled: boolean;
}

export interface Action {
    isMajor: boolean;
    action: string;
    resolves: Resolve[];
    module: string;
    target: string;
    depth?: number;
}

export interface Finding {
    version: string;
    paths: string[];
}

export interface FoundBy {
    link: string;
    name: string;
}

export interface ReportedBy {
    link: string;
    name: string;
}

export interface Metadata {
    module_type: string;
    exploitability: number;
    affected_components: string;
}

export interface KeyMetadata {
    module_type: string;
    exploitability: number;
    affected_components: string;
}

export interface Advisory {
    findings: Finding[];
    id: number;
    created: Date;
    updated: Date;
    deleted?: any;
    title: string;
    found_by: FoundBy;
    reported_by: ReportedBy;
    module_name: string;
    cves: any[];
    vulnerable_versions: string;
    patched_versions: string;
    overview: string;
    recommendation: string;
    references: string;
    access: string;
    severity: string;
    cwe: string;
    metadata: KeyMetadata;
    url: string;
}

export interface Vulnerabilities {
    info: number;
    low: number;
    moderate: number;
    high: number;
    critical: number;
}

export interface Metadata {
    vulnerabilities: Vulnerabilities;
    dependencies: number;
    devDependencies: number;
    optionalDependencies: number;
    totalDependencies: number;
}

export interface Report {
    actions: Action[];
    advisories: any;
    muted: any[];
    metadata: Metadata;
    runId: string;
}