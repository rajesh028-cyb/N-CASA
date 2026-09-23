import React, { useState, useEffect, useRef } from 'react';
import {
  UploadCloud,
  File,
  X,
  CheckCircle2,
  AlertCircle,
  AlertTriangle,
  Loader2,
  Shield,
  ClipboardList,
  Cpu,
  Layers,
  ChevronDown,
  ChevronUp,
  FileText,
  Search,
  HelpCircle,
  Code2,
  Terminal,
  Server,
  Globe,
  Lock,
  Radio,
  FileCode,
  Sparkles,
  Eye,
  Download,
} from 'lucide-react';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import {
  uploadAudit,
  getAudit,
  triggerVendorDetection,
  getDetectionResults,
  triggerConfigurationParsing,
  getParsingResults,
  triggerConfigurationNormalization,
  getNormalizationResults,
  triggerComplianceEvaluation,
  getComplianceResults,
  triggerFindingsGeneration,
  getAuditFindings,
  triggerRemediationGeneration,
  getAuditRemediation,
  triggerAiAnalysis,
  getAiAnalysis,
} from '../api/audits';
import { generateReport, fetchAuditReports, getReportHtmlUrl, getReportPdfUrl } from '../api/reports';
import { ApiError } from '../api/client';

// ── Framework definitions ─────────────────────────────────────────────────────
const FRAMEWORKS = [
  {
    id: 'cis',
    name: 'CIS Benchmarks',
    backendValue: 'CIS',
    description: 'Center for Internet Security configuration benchmarks for network devices.',
    available: true,
  },
  {
    id: 'nist',
    name: 'NIST SP 800-53',
    backendValue: 'NIST',
    description: 'NIST security and privacy controls for federal information systems.',
    available: true,
  },
  {
    id: 'stig',
    name: 'DISA STIG',
    backendValue: 'STIG',
    description: 'Defense Information Systems Agency Security Technical Implementation Guides.',
    available: true,
  },
  {
    id: 'iso27001',
    name: 'ISO/IEC 27001',
    backendValue: 'ISO27001',
    description: 'International standard for information security management systems.',
    available: false,
  },
];

const ACCEPTED_EXTENSIONS = ['.zip', '.cfg', '.conf', '.txt'];
const MAX_BYTES = 50 * 1024 * 1024; // 50 MB

// ── UI pipeline states ────────────────────────────────────────────────────────
const STATE = {
  EMPTY:                  'EMPTY',
  SELECTED:               'SELECTED',
  UPLOADING:              'UPLOADING',
  READY_FOR_DETECTION:    'READY_FOR_DETECTION',
  DETECTING:              'DETECTING',
  DETECTION_COMPLETE:     'DETECTION_COMPLETE',
  PARSING:                'PARSING',
  PARSING_COMPLETE:       'PARSING_COMPLETE',
  NORMALIZING:            'NORMALIZING',
  NORMALIZATION_COMPLETE: 'NORMALIZATION_COMPLETE',
  EVALUATING_COMPLIANCE:  'EVALUATING_COMPLIANCE',
  COMPLIANCE_COMPLETE:    'COMPLIANCE_COMPLETE',
  GENERATING_FINDINGS:    'GENERATING_FINDINGS',
  FINDINGS_COMPLETE:      'FINDINGS_COMPLETE',
  GENERATING_REMEDIATION: 'GENERATING_REMEDIATION',
  REMEDIATION_COMPLETE:   'REMEDIATION_COMPLETE',
  ANALYZING_AI:           'ANALYZING_AI',
  AI_COMPLETE:            'AI_COMPLETE',
  GENERATING_REPORT:      'GENERATING_REPORT',
  REPORT_COMPLETE:        'REPORT_COMPLETE',
  ERROR:                  'ERROR',
};


// ── Helpers ───────────────────────────────────────────────────────────────────
function formatBytes(bytes) {
  if (!bytes && bytes !== 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function friendlyError(err) {
  if (!(err instanceof ApiError)) return err?.message || 'An unexpected error occurred.';
  if (err.status === 0)   return 'Backend unavailable. Please make sure the N-CASA API server is running.';
  if (err.status === 400) return err.message;
  if (err.status === 413) return err.message;
  if (err.status === 422) return 'Invalid request. Check the file and framework selection.';
  return err.message || `Operation failed (HTTP ${err.status}).`;
}

function VendorBadge({ vendor }) {
  if (vendor === 'Cisco' || vendor === 'CISCO') {
    return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-blue-900/40 text-blue-300 border border-blue-700/50">Cisco</span>;
  }
  if (vendor === 'Juniper' || vendor === 'JUNIPER') {
    return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-emerald-900/40 text-emerald-300 border border-emerald-700/50">Juniper</span>;
  }
  if (vendor === 'Fortinet' || vendor === 'FORTINET') {
    return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-red-900/40 text-red-300 border border-red-700/50">Fortinet</span>;
  }
  return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-ncasa-surface2 text-ncasa-muted border border-ncasa-border">Unknown</span>;
}

function CategoryBadge({ category }) {
  if (category === 'STRONG') {
    return <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-amber-900/30 text-amber-300 border border-amber-700/40">+50 STRONG</span>;
  }
  if (category === 'MEDIUM') {
    return <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-blue-900/30 text-blue-300 border border-blue-700/40">+20 MEDIUM</span>;
  }
  return <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-ncasa-surface2 text-ncasa-muted border border-ncasa-border">+5 WEAK</span>;
}

// ── Stepper Header ────────────────────────────────────────────────────────────
function PipelineStepper({ uploadState, hasUnknownVendor }) {
  const isDone = (targetStates) => targetStates.includes(uploadState);

  const steps = [
    { num: 1, label: 'Ingestion', state: 'COMPLETE' },
    {
      num: 2,
      label: 'Detection',
      state: uploadState === STATE.READY_FOR_DETECTION ? 'PENDING' : uploadState === STATE.DETECTING ? 'RUNNING' : 'COMPLETE',
    },
    {
      num: 3,
      label: 'Parsing',
      state: [STATE.READY_FOR_DETECTION, STATE.DETECTING, STATE.DETECTION_COMPLETE].includes(uploadState)
        ? (uploadState === STATE.PARSING ? 'RUNNING' : 'PENDING')
        : 'COMPLETE',
    },
    {
      num: 4,
      label: 'Normalization',
      state: [STATE.READY_FOR_DETECTION, STATE.DETECTING, STATE.DETECTION_COMPLETE, STATE.PARSING, STATE.PARSING_COMPLETE].includes(uploadState)
        ? (uploadState === STATE.NORMALIZING ? 'RUNNING' : 'PENDING')
        : 'COMPLETE',
    },
    {
      num: 5,
      label: 'Compliance',
      state: [STATE.READY_FOR_DETECTION, STATE.DETECTING, STATE.DETECTION_COMPLETE, STATE.PARSING, STATE.PARSING_COMPLETE, STATE.NORMALIZING, STATE.NORMALIZATION_COMPLETE].includes(uploadState)
        ? (uploadState === STATE.EVALUATING_COMPLIANCE ? 'RUNNING' : 'PENDING')
        : 'COMPLETE',
    },
    {
      num: 6,
      label: 'Findings',
      state: uploadState === STATE.GENERATING_FINDINGS
        ? 'RUNNING'
        : [STATE.FINDINGS_COMPLETE, STATE.GENERATING_REMEDIATION, STATE.REMEDIATION_COMPLETE, STATE.ANALYZING_AI, STATE.AI_COMPLETE, STATE.GENERATING_REPORT, STATE.REPORT_COMPLETE].includes(uploadState)
        ? 'COMPLETE'
        : 'PENDING',
    },
    {
      num: 7,
      label: 'Remediation',
      state: uploadState === STATE.GENERATING_REMEDIATION
        ? 'RUNNING'
        : [STATE.REMEDIATION_COMPLETE, STATE.ANALYZING_AI, STATE.AI_COMPLETE, STATE.GENERATING_REPORT, STATE.REPORT_COMPLETE].includes(uploadState)
        ? 'COMPLETE'
        : 'PENDING',
    },
    {
      num: 8,
      label: 'AI Analysis',
      state: !hasUnknownVendor
        ? 'NOT_REQUIRED'
        : uploadState === STATE.ANALYZING_AI
        ? 'RUNNING'
        : [STATE.AI_COMPLETE, STATE.GENERATING_REPORT, STATE.REPORT_COMPLETE].includes(uploadState)
        ? 'COMPLETE'
        : 'AVAILABLE',
    },
    {
      num: 9,
      label: 'Report',
      state: uploadState === STATE.GENERATING_REPORT
        ? 'RUNNING'
        : uploadState === STATE.REPORT_COMPLETE
        ? 'COMPLETE'
        : 'PENDING',
    },
  ];

  return (
    <div className="bg-ncasa-surface border border-ncasa-border rounded p-4 mb-4">
      <p className="text-[11px] font-semibold uppercase tracking-wider text-ncasa-muted mb-3">N-CASA Audit Stepper Progress</p>
      <div className="grid grid-cols-3 sm:grid-cols-9 gap-1.5 text-center">
        {steps.map((st) => (
          <div
            key={st.num}
            className={`p-2 rounded border flex flex-col items-center justify-between text-[11px] ${
              st.state === 'COMPLETE'
                ? 'bg-status-pass-bg/40 border-status-pass/40 text-status-pass'
                : st.state === 'RUNNING'
                ? 'bg-ncasa-accent-l/20 border-ncasa-accent/50 text-ncasa-accent animate-pulse font-bold'
                : st.state === 'NOT_REQUIRED'
                ? 'bg-ncasa-surface2 border-ncasa-border text-ncasa-muted opacity-60'
                : st.state === 'AVAILABLE'
                ? 'bg-amber-950/20 border-amber-500/30 text-amber-300 font-bold'
                : 'bg-ncasa-surface2 border-ncasa-border text-ncasa-muted'
            }`}
          >
            <span className="font-mono text-[9px] font-bold">Step {st.num}</span>
            <span className="font-semibold truncate w-full mt-0.5">{st.label}</span>
            <span className="text-[9px] font-mono mt-1 uppercase font-bold">
              {st.state === 'COMPLETE' ? '✓ DONE' : st.state === 'RUNNING' ? '● RUNNING' : st.state === 'NOT_REQUIRED' ? 'N/A' : st.state}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Main Component ────────────────────────────────────────────────────────────
export default function NewAudit() {
  const [uploadState, setUploadState] = useState(STATE.EMPTY);
  const [selectedFile, setSelectedFile] = useState(null);
  const [dragging, setDragging]         = useState(false);
  const [selectedFramework, setSelectedFramework] = useState('cis');
  const [errorMessage, setErrorMessage] = useState('');

  // API Data States
  const [auditData, setAuditData]                   = useState(null); // AuditDetailResponse
  const [detectionSummary, setDetectionSummary]     = useState(null); // AuditDetectionSummary
  const [parsingSummary, setParsingSummary]         = useState(null); // AuditParsingSummary
  const [normalizationSummary, setNormalizationSummary] = useState(null); // AuditNormalizationSummary
  const [complianceSummary, setComplianceSummary]   = useState(null); // AuditComplianceSummary
  const [findingsSummary, setFindingsSummary]       = useState(null); // AuditFindingsSummary
  const [remediationSummary, setRemediationSummary] = useState(null); // AuditRemediationSummary
  const [aiAnalysisSummary, setAiAnalysisSummary]   = useState(null); // AIAnalysisSummary
  const [reportMetadata, setReportMetadata]         = useState(null); // ReportMetadata

  const [isAnalyzingAi, setIsAnalyzingAi]           = useState(false);
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);

  const [expandedEvidence, setExpandedEvidence]     = useState({});   // { file_id: boolean }
  const [expandedParsedData, setExpandedParsedData] = useState({}); // { file_id: boolean }
  const [expandedNormalizedData, setExpandedNormalizedData] = useState({}); // { file_id: boolean }
  const [expandedControlData, setExpandedControlData]       = useState({}); // { control_id: boolean }
  const [compFrameworkFilter, setCompFrameworkFilter]       = useState('ALL');
  const [compSeverityFilter, setCompSeverityFilter]         = useState('ALL');
  const fileInputRef = useRef(null);
  const pipelineRunningRef = useRef(false);


  // ── File selection / validation ──────────────────────────────────────────
  const handleFile = (file) => {
    if (!file) return;

    const ext = '.' + file.name.split('.').pop().toLowerCase();
    if (!ACCEPTED_EXTENSIONS.includes(ext)) {
      setErrorMessage(`Unsupported file type "${ext}". Allowed: ${ACCEPTED_EXTENSIONS.join(', ')}`);
      setUploadState(STATE.ERROR);
      return;
    }
    if (file.size > MAX_BYTES) {
      setErrorMessage(`File exceeds the 50 MB limit (${formatBytes(file.size)}).`);
      setUploadState(STATE.ERROR);
      return;
    }

    setSelectedFile(file);
    setErrorMessage('');
    setAuditData(null);
    setDetectionSummary(null);
    setParsingSummary(null);
    setNormalizationSummary(null);
    setComplianceSummary(null);
    setUploadState(STATE.SELECTED);
  };

  const handleRemoveFile = () => {
    setSelectedFile(null);
    setAuditData(null);
    setDetectionSummary(null);
    setParsingSummary(null);
    setNormalizationSummary(null);
    setComplianceSummary(null);
    setErrorMessage('');
    setUploadState(STATE.EMPTY);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  // ── Drag & drop ──────────────────────────────────────────────────────────
  const handleDrop      = (e) => { e.preventDefault(); setDragging(false); handleFile(e.dataTransfer.files?.[0]); };
  const handleDragOver  = (e) => { e.preventDefault(); setDragging(true); };
  const handleDragLeave = ()  => setDragging(false);
  const handleBrowse    = ()  => fileInputRef.current?.click();

  // ── Page Refresh / Existing Audit Recovery ────────────────────────────────
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const auditIdParam = urlParams.get('audit_id');
    if (auditIdParam) {
      loadExistingAudit(auditIdParam);
    }
  }, []);

  const loadExistingAudit = async (auditId) => {
    setUploadState(STATE.UPLOADING);
    setErrorMessage('');
    try {
      const detail = await getAudit(auditId);
      setAuditData(detail);

      try { const det = await getDetectionResults(auditId); setDetectionSummary(det); } catch (e) {}
      try { const parse = await getParsingResults(auditId); setParsingSummary(parse); } catch (e) {}
      try { const norm = await getNormalizationResults(auditId); setNormalizationSummary(norm); } catch (e) {}
      try { const comp = await getComplianceResults(auditId); setComplianceSummary(comp); } catch (e) {}
      try { const find = await getAuditFindings(auditId); setFindingsSummary(find); } catch (e) {}
      try { const rem = await getAuditRemediation(auditId); setRemediationSummary(rem); } catch (e) {}
      try { const ai = await getAiAnalysis(auditId); setAiAnalysisSummary(ai); } catch (e) {}
      try {
        const reps = await fetchAuditReports(auditId);
        if (reps && reps.length > 0) setReportMetadata(reps[0]);
      } catch (e) {}

      setUploadState(STATE.REPORT_COMPLETE);
    } catch (err) {
      setErrorMessage(friendlyError(err));
      setUploadState(STATE.ERROR);
    }
  };

  // ── Automated Pipeline Runner ──────────────────────────────────────────────
  const executePipeline = async (auditId) => {
    if (pipelineRunningRef.current) return;
    pipelineRunningRef.current = true;
    try {
      // Step 2: Detection
      setUploadState(STATE.DETECTING);
      const det = await triggerVendorDetection(auditId);
      setDetectionSummary(det);
      setUploadState(STATE.DETECTION_COMPLETE);

      // Step 3: Parsing
      setUploadState(STATE.PARSING);
      const parse = await triggerConfigurationParsing(auditId);
      setParsingSummary(parse);
      setUploadState(STATE.PARSING_COMPLETE);

      // Step 4: Normalization
      setUploadState(STATE.NORMALIZING);
      const norm = await triggerConfigurationNormalization(auditId);
      setNormalizationSummary(norm);
      setUploadState(STATE.NORMALIZATION_COMPLETE);

      // Step 5: Compliance
      setUploadState(STATE.EVALUATING_COMPLIANCE);
      const comp = await triggerComplianceEvaluation(auditId);
      setComplianceSummary(comp);
      setUploadState(STATE.COMPLIANCE_COMPLETE);

      // Step 6: Findings
      setUploadState(STATE.GENERATING_FINDINGS);
      const find = await triggerFindingsGeneration(auditId);
      setFindingsSummary(find);
      setUploadState(STATE.FINDINGS_COMPLETE);

      // Step 7: Remediation
      setUploadState(STATE.GENERATING_REMEDIATION);
      const rem = await triggerRemediationGeneration(auditId);
      setRemediationSummary(rem);
      setUploadState(STATE.REMEDIATION_COMPLETE);

      // Step 8: AI Analysis (for unknown vendors)
      const hasUnknown = det?.files?.some((f) => f.vendor === 'Unknown' || f.vendor === 'UNKNOWN');
      if (hasUnknown) {
        setIsAnalyzingAi(true);
        setUploadState(STATE.ANALYZING_AI);
        try {
          const ai = await triggerAiAnalysis(auditId);
          setAiAnalysisSummary(ai);
        } catch (aiErr) {
          console.warn('AI analysis notice:', aiErr);
        } finally {
          setIsAnalyzingAi(false);
          setUploadState(STATE.AI_COMPLETE);
        }
      } else {
        setUploadState(STATE.AI_COMPLETE);
      }

      // Step 9: Report Generation
      setIsGeneratingReport(true);
      setUploadState(STATE.GENERATING_REPORT);
      try {
        const rep = await generateReport(auditId);
        setReportMetadata(rep);
      } catch (repErr) {
        console.warn('Report generation notice:', repErr);
      } finally {
        setIsGeneratingReport(false);
        setUploadState(STATE.REPORT_COMPLETE);
      }

      // Fetch final persisted audit details
      const detail = await getAudit(auditId);
      setAuditData(detail);

    } catch (err) {
      console.error('Audit pipeline execution error:', err);
      setErrorMessage(friendlyError(err));
      setUploadState(STATE.ERROR);
    } finally {
      pipelineRunningRef.current = false;
    }
  };

  // ── Submit Upload (Block 2 & 3) ──────────────────────────────────────────
  const handleStartAudit = async () => {
    if (!selectedFile || uploadState === STATE.UPLOADING || pipelineRunningRef.current) return;

    const fw = FRAMEWORKS.find((f) => f.id === selectedFramework);
    if (!fw) return;

    setUploadState(STATE.UPLOADING);
    setErrorMessage('');
    setAuditData(null);
    setDetectionSummary(null);
    setParsingSummary(null);
    setNormalizationSummary(null);
    setComplianceSummary(null);
    setFindingsSummary(null);
    setRemediationSummary(null);
    setAiAnalysisSummary(null);
    setReportMetadata(null);

    let result;
    try {
      result = await uploadAudit(selectedFile, fw.backendValue);
      setAuditData(result);
      setUploadState(STATE.READY_FOR_DETECTION);
    } catch (err) {
      setErrorMessage(friendlyError(err));
      setUploadState(STATE.ERROR);
      return;
    }

    // Automatically trigger end-to-end audit execution
    await executePipeline(result.audit_id);
  };

  // ── Trigger Vendor Detection (Block 4) ───────────────────────────────────
  const handleRunDetection = async () => {
    if (!auditData?.audit_id) return;

    setUploadState(STATE.DETECTING);
    setErrorMessage('');

    try {
      const summary = await triggerVendorDetection(auditData.audit_id);
      setDetectionSummary(summary);
      setUploadState(STATE.DETECTION_COMPLETE);
    } catch (err) {
      setErrorMessage(friendlyError(err));
      setUploadState(STATE.READY_FOR_DETECTION);
    }
  };

  // ── Trigger Configuration Parsing (Block 5) ──────────────────────────────
  const handleRunParsing = async () => {
    if (!auditData?.audit_id) return;

    setUploadState(STATE.PARSING);
    setErrorMessage('');

    try {
      const summary = await triggerConfigurationParsing(auditData.audit_id);
      setParsingSummary(summary);
      setUploadState(STATE.PARSING_COMPLETE);
    } catch (err) {
      setErrorMessage(friendlyError(err));
      setUploadState(STATE.DETECTION_COMPLETE);
    }
  };

  // ── Trigger Vendor-Neutral Normalization (Block 6) ─────────────────────────
  const handleRunNormalization = async () => {
    if (!auditData?.audit_id) return;

    setUploadState(STATE.NORMALIZING);
    setErrorMessage('');

    try {
      const summary = await triggerConfigurationNormalization(auditData.audit_id);
      setNormalizationSummary(summary);
      setUploadState(STATE.NORMALIZATION_COMPLETE);
    } catch (err) {
      setErrorMessage(friendlyError(err));
      setUploadState(STATE.PARSING_COMPLETE);
    }
  };

  // ── Trigger Deterministic Compliance Audit (Block 7) ─────────────────────
  const handleRunCompliance = async () => {
    if (!auditData?.audit_id) return;

    setUploadState(STATE.EVALUATING_COMPLIANCE);
    setErrorMessage('');

    try {
      const summary = await triggerComplianceEvaluation(auditData.audit_id);
      setComplianceSummary(summary);
      setUploadState(STATE.COMPLIANCE_COMPLETE);
    } catch (err) {
      setErrorMessage(friendlyError(err));
      setUploadState(STATE.NORMALIZATION_COMPLETE);
    }
  };

  // ── Trigger Findings Engine (Block 8) ────────────────────────────────────
  const handleGenerateFindings = async () => {
    if (!auditData?.audit_id) return;

    setUploadState(STATE.GENERATING_FINDINGS);
    setErrorMessage('');

    try {
      const summary = await triggerFindingsGeneration(auditData.audit_id);
      setFindingsSummary(summary);
      setUploadState(STATE.FINDINGS_COMPLETE);
    } catch (err) {
      setErrorMessage(friendlyError(err));
      setUploadState(STATE.COMPLIANCE_COMPLETE);
    }
  };

  // ── Trigger Remediation Engine (Block 9) ──────────────────────────────────
  const handleGenerateRemediation = async () => {
    if (!auditData?.audit_id) return;

    setUploadState(STATE.GENERATING_REMEDIATION);
    setErrorMessage('');

    try {
      const summary = await triggerRemediationGeneration(auditData.audit_id);
      setRemediationSummary(summary);
      setUploadState(STATE.REMEDIATION_COMPLETE);
    } catch (err) {
      setErrorMessage(friendlyError(err));
      setUploadState(STATE.FINDINGS_COMPLETE);
    }
  };

  // ── Trigger AI Analysis for Unknown Vendors (Block 10) ───────────────────
  const handleRunAiAnalysis = async () => {
    if (!auditData?.audit_id) return;

    setIsAnalyzingAi(true);
    setUploadState(STATE.ANALYZING_AI);
    setErrorMessage('');

    try {
      const summary = await triggerAiAnalysis(auditData.audit_id);
      setAiAnalysisSummary(summary);
      setUploadState(STATE.AI_COMPLETE);
    } catch (err) {
      setErrorMessage(friendlyError(err));
      setUploadState(STATE.REMEDIATION_COMPLETE);
    } finally {
      setIsAnalyzingAi(false);
    }
  };

  // ── Trigger Report Generation (Block 12) ──────────────────────────────────
  const handleGenerateReportSnapshot = async () => {
    if (!auditData?.audit_id) return;

    setIsGeneratingReport(true);
    setUploadState(STATE.GENERATING_REPORT);
    setErrorMessage('');

    try {
      const meta = await generateReport(auditData.audit_id);
      setReportMetadata(meta);
      setUploadState(STATE.REPORT_COMPLETE);
    } catch (err) {
      setErrorMessage(friendlyError(err));
      setUploadState(STATE.REMEDIATION_COMPLETE);
    } finally {
      setIsGeneratingReport(false);
    }
  };

  const handleReset = () => {
    setSelectedFile(null);
    setAuditData(null);
    setDetectionSummary(null);
    setParsingSummary(null);
    setNormalizationSummary(null);
    setComplianceSummary(null);
    setFindingsSummary(null);
    setRemediationSummary(null);
    setAiAnalysisSummary(null);
    setReportMetadata(null);
    setErrorMessage('');
    setExpandedEvidence({});
    setExpandedParsedData({});
    setExpandedNormalizedData({});
    setExpandedControlData({});
    setCompFrameworkFilter('ALL');
    setCompSeverityFilter('ALL');
    setUploadState(STATE.EMPTY);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };


  const toggleEvidence = (fileId) => {
    setExpandedEvidence((prev) => ({ ...prev, [fileId]: !prev[fileId] }));
  };

  const toggleParsedData = (fileId) => {
    setExpandedParsedData((prev) => ({ ...prev, [fileId]: !prev[fileId] }));
  };

  const toggleNormalizedData = (fileId) => {
    setExpandedNormalizedData((prev) => ({ ...prev, [fileId]: !prev[fileId] }));
  };

  const toggleControlData = (controlId) => {
    setExpandedControlData((prev) => ({ ...prev, [controlId]: !prev[controlId] }));
  };

  const isUploading            = uploadState === STATE.UPLOADING;
  const isDetecting            = uploadState === STATE.DETECTING;
  const isParsing              = uploadState === STATE.PARSING;
  const isNormalizing          = uploadState === STATE.NORMALIZING;
  const isEvaluatingCompliance = uploadState === STATE.EVALUATING_COMPLIANCE;
  const isGeneratingFindings   = uploadState === STATE.GENERATING_FINDINGS;
  const isGeneratingRemediation = uploadState === STATE.GENERATING_REMEDIATION;

  const isPostUpload = [
    STATE.READY_FOR_DETECTION,
    STATE.DETECTING,
    STATE.DETECTION_COMPLETE,
    STATE.PARSING,
    STATE.PARSING_COMPLETE,
    STATE.NORMALIZING,
    STATE.NORMALIZATION_COMPLETE,
    STATE.EVALUATING_COMPLIANCE,
    STATE.COMPLIANCE_COMPLETE,
    STATE.GENERATING_FINDINGS,
    STATE.FINDINGS_COMPLETE,
    STATE.GENERATING_REMEDIATION,
    STATE.REMEDIATION_COMPLETE,
    STATE.ANALYZING_AI,
    STATE.AI_COMPLETE,
    STATE.GENERATING_REPORT,
    STATE.REPORT_COMPLETE,
  ].includes(uploadState);

  const inventory = auditData?.inventory;
  const hasUnknownVendor = detectionSummary?.files?.some((f) => f.vendor === 'Unknown');

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Page header */}
      <div>
        <h1 className="text-xl font-bold text-ncasa-text">New Security Audit</h1>
        <p className="text-sm text-ncasa-muted mt-0.5">
          Ingest, discover, detect, and parse multi-vendor network configurations for compliance auditing.
        </p>
      </div>

      {/* ── POST-UPLOAD PIPELINE VIEWS ──────────────────────────────────── */}
      {isPostUpload && auditData && (
        <div className="space-y-6">
          {/* Stepper Header (9 Steps) */}
          <PipelineStepper uploadState={uploadState} hasUnknownVendor={hasUnknownVendor} />

          {/* Card 1: Audit Overview */}

          <div className="bg-ncasa-surface border border-ncasa-border rounded p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-full bg-ncasa-accent-l/20 border border-ncasa-accent/30">
                  <CheckCircle2 size={20} className="text-ncasa-accent" />
                </div>
                <div>
                  <p className="text-sm font-semibold text-ncasa-text">Configuration Ingested & Verified</p>
                  <p className="text-xs text-ncasa-muted mt-0.5">
                    Job ID <span className="font-mono text-ncasa-accent font-semibold">{auditData.audit_id}</span> pipeline state:
                  </p>
                </div>
              </div>
              <span className="text-xs font-mono font-bold px-2.5 py-1 rounded bg-ncasa-surface2 text-ncasa-subtle border border-ncasa-border">
                {uploadState}
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
              {[
                { label: 'Audit ID',      value: auditData.audit_id,                  mono: true, accent: true },
                { label: 'Framework',     value: auditData.framework,                 mono: false },
                { label: 'Original File', value: auditData.filename,                  mono: true },
                { label: 'Uploaded Size', value: formatBytes(auditData.file_size || selectedFile?.size || 0), mono: false },
              ].map(({ label, value, mono, accent }) => (
                <div key={label} className="bg-ncasa-surface2 border border-ncasa-border rounded px-3 py-2.5">
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-ncasa-muted mb-1">{label}</p>
                  <p className={`text-sm font-semibold truncate ${mono ? 'font-mono' : ''} ${accent ? 'text-ncasa-accent' : 'text-ncasa-text'}`}>
                    {value}
                  </p>
                </div>
              ))}
            </div>
          </div>

          {/* Card 2: Configuration Inventory (Block 3) */}
          {inventory && (
            <div className="bg-ncasa-surface border border-ncasa-border rounded p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Layers size={18} className="text-ncasa-accent" />
                  <h3 className="text-sm font-bold text-ncasa-text">Configuration Inventory</h3>
                </div>
                <div className="flex items-center gap-2 text-xs text-ncasa-muted">
                  <span className="font-mono text-ncasa-text font-bold">{inventory.valid_configs_count}</span> valid config file(s) discovered
                </div>
              </div>

              {/* Summary stat strip */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-ncasa-surface2 p-3 rounded border border-ncasa-border text-center">
                <div>
                  <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Discovered Files</p>
                  <p className="text-lg font-bold text-ncasa-text font-mono">{inventory.total_files_discovered}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Valid Configs</p>
                  <p className="text-lg font-bold text-status-pass font-mono">{inventory.valid_configs_count}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Total Lines</p>
                  <p className="text-lg font-bold text-ncasa-accent font-mono">{(inventory.total_lines || 0).toLocaleString()}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Skipped Files</p>
                  <p className="text-lg font-bold text-ncasa-muted font-mono">{inventory.skipped_files_count || 0}</p>
                </div>
              </div>

              {/* Discovered files list table */}
              <div className="border border-ncasa-border rounded overflow-hidden">
                <table className="w-full text-left text-xs">
                  <thead className="bg-ncasa-surface2 text-ncasa-muted border-b border-ncasa-border uppercase text-[10px]">
                    <tr>
                      <th className="p-2.5 font-semibold">File ID</th>
                      <th className="p-2.5 font-semibold">Relative Path</th>
                      <th className="p-2.5 font-semibold">Candidate Hostname</th>
                      <th className="p-2.5 font-semibold text-right">Lines</th>
                      <th className="p-2.5 font-semibold text-right">Size</th>
                      <th className="p-2.5 font-semibold text-center">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-ncasa-border font-mono">
                    {(inventory.files || []).map((file) => (
                      <tr key={file.file_id} className="hover:bg-ncasa-surface2/50 transition-colors">
                        <td className="p-2.5 font-bold text-ncasa-accent">{file.file_id}</td>
                        <td className="p-2.5 text-ncasa-text">{file.relative_path}</td>
                        <td className="p-2.5 text-ncasa-subtle">
                          {file.candidate_hostname ? (
                            <span className="bg-ncasa-surface2 px-1.5 py-0.5 rounded text-ncasa-text font-bold">
                              {file.candidate_hostname}
                            </span>
                          ) : (
                            <span className="text-ncasa-muted italic font-sans text-[11px]">Not visible</span>
                          )}
                        </td>
                        <td className="p-2.5 text-right text-ncasa-text">{file.line_count || '-'}</td>
                        <td className="p-2.5 text-right text-ncasa-muted">{formatBytes(file.file_size)}</td>
                        <td className="p-2.5 text-center">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${file.status === 'VALID' ? 'bg-status-pass-bg text-status-pass border border-status-pass/30' : 'bg-ncasa-surface2 text-ncasa-muted'}`}>
                            {file.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Action area: Trigger Vendor Detection */}
              {uploadState === STATE.READY_FOR_DETECTION && (
                <div className="pt-2 flex items-center justify-between">
                  <p className="text-xs text-ncasa-muted">
                    Next step: analyze syntax patterns to determine vendor & device classification.
                  </p>
                  <Button
                    variant="primary"
                    size="md"
                    onClick={handleRunDetection}
                    icon={Search}
                  >
                    Detect Vendor & Device
                  </Button>
                </div>
              )}

              {isDetecting && (
                <div className="pt-2 flex items-center gap-3 text-sm text-ncasa-accent animate-pulse">
                  <Loader2 size={18} className="animate-spin" />
                  <span>Running deterministic vendor detection engine across inventory…</span>
                </div>
              )}
            </div>
          )}

          {/* Card 3: Vendor & Device Detection Results (Block 4) */}
          {detectionSummary && (
            <div className="bg-ncasa-surface border border-ncasa-border rounded p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Cpu size={18} className="text-ncasa-accent" />
                  <h3 className="text-sm font-bold text-ncasa-text">Vendor & Device Detection Results</h3>
                </div>
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-status-pass-bg text-status-pass border border-status-pass/30">
                  DETECTION COMPLETE
                </span>
              </div>

              {/* Detection results table */}
              <div className="border border-ncasa-border rounded overflow-hidden">
                <table className="w-full text-left text-xs">
                  <thead className="bg-ncasa-surface2 text-ncasa-muted border-b border-ncasa-border uppercase text-[10px]">
                    <tr>
                      <th className="p-2.5 font-semibold">File</th>
                      <th className="p-2.5 font-semibold">Vendor</th>
                      <th className="p-2.5 font-semibold">Device Type</th>
                      <th className="p-2.5 font-semibold">Confidence</th>
                      <th className="p-2.5 font-semibold">Method</th>
                      <th className="p-2.5 font-semibold">Status</th>
                      <th className="p-2.5 font-semibold text-right">Evidence</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-ncasa-border">
                    {(detectionSummary?.files || []).map((res) => {
                      const isExpanded = !!expandedEvidence[res.file_id];
                      return (
                        <React.Fragment key={res.file_id}>
                          <tr className="hover:bg-ncasa-surface2/50 transition-colors">
                            <td className="p-2.5 font-mono text-ncasa-text font-semibold">
                              <div>{res.relative_path}</div>
                              <span className="text-[10px] text-ncasa-muted">{res.file_id}</span>
                            </td>
                            <td className="p-2.5"><VendorBadge vendor={res.vendor} /></td>
                            <td className="p-2.5 font-semibold text-ncasa-text">{res.device_type}</td>
                            <td className="p-2.5 font-mono">
                              <div className="flex items-center gap-2">
                                <span>{Math.round(res.confidence * 100)}%</span>
                                <div className="w-12 h-1.5 rounded-full bg-ncasa-surface2 overflow-hidden">
                                  <div
                                    className={`h-full ${res.confidence >= 0.7 ? 'bg-status-pass' : res.confidence > 0 ? 'bg-ncasa-accent' : 'bg-ncasa-muted'}`}
                                    style={{ width: `${Math.round(res.confidence * 100)}%` }}
                                  />
                                </div>
                              </div>
                            </td>
                            <td className="p-2.5 text-ncasa-subtle text-[11px]">{res.method}</td>
                            <td className="p-2.5">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${res.status === 'KNOWN' ? 'bg-status-pass-bg text-status-pass border border-status-pass/30' : 'bg-amber-900/30 text-amber-300 border border-amber-700/40'}`}>
                                {res.status === 'KNOWN' ? 'Known' : 'AI Analysis Required'}
                              </span>
                            </td>
                            <td className="p-2.5 text-right">
                              <button
                                onClick={() => toggleEvidence(res.file_id)}
                                className="inline-flex items-center gap-1 text-xs text-ncasa-accent hover:underline font-medium"
                              >
                                {(res.evidence || []).length} item(s)
                                {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                              </button>
                            </td>
                          </tr>

                          {/* Expandable evidence drawer */}
                          {isExpanded && (
                            <tr>
                              <td colSpan={7} className="bg-ncasa-surface2/60 p-3 border-b border-ncasa-border">
                                <div className="space-y-2">
                                  <p className="text-[10px] font-bold uppercase tracking-wider text-ncasa-muted">
                                    Detection Evidence Details for {res.file_id} ({res.relative_path})
                                  </p>
                                  {(res.evidence || []).length === 0 ? (
                                    <p className="text-xs text-ncasa-muted italic">No signature indicators matched.</p>
                                  ) : (
                                    <div className="space-y-1.5 font-mono text-xs">
                                      {(res.evidence || []).map((ev, idx) => (
                                        <div key={idx} className="flex items-center justify-between bg-ncasa-surface border border-ncasa-border px-3 py-1.5 rounded">
                                          <div className="flex items-center gap-3">
                                            <span className="text-ncasa-muted font-bold">Line {ev.line}:</span>
                                            <span className="text-ncasa-text font-semibold">{ev.indicator}</span>
                                          </div>
                                          <CategoryBadge category={ev.category} />
                                        </div>
                                      ))}
                                    </div>
                                  )}
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {/* UNKNOWN vendor disclaimer banner */}
              {hasUnknownVendor && (
                <div className="flex items-start gap-3 p-3.5 rounded border border-amber-700/40 bg-amber-950/20 text-xs text-amber-200">
                  <HelpCircle size={18} className="text-amber-400 shrink-0 mt-0.5" />
                  <div>
                    <p className="font-semibold text-amber-300 mb-0.5">Unknown Vendor Signature Detected</p>
                    <p className="leading-relaxed">
                      Vendor could not be determined using known signatures. AI-assisted configuration understanding will be available in a later processing stage (Block 10).
                    </p>
                  </div>
                </div>
              )}

              {/* Action area: Trigger Configuration Parsing */}
              {uploadState === STATE.DETECTION_COMPLETE && (
                <div className="pt-2 flex items-center justify-between">
                  <p className="text-xs text-ncasa-muted">
                    Next step: parse known-vendor configuration structures into structured data with line references.
                  </p>
                  <Button
                    variant="primary"
                    size="md"
                    onClick={handleRunParsing}
                    icon={Code2}
                  >
                    Parse Configurations
                  </Button>
                </div>
              )}

              {isParsing && (
                <div className="pt-2 flex items-center gap-3 text-sm text-ncasa-accent animate-pulse">
                  <Loader2 size={18} className="animate-spin" />
                  <span>Parsing vendor configurations and mapping line evidence…</span>
                </div>
              )}
            </div>
          )}

          {/* Card 4: Vendor-Specific Configuration Parsing Results (Block 5) */}
          {parsingSummary && (
            <div className="bg-ncasa-surface border border-ncasa-border rounded p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Code2 size={18} className="text-ncasa-accent" />
                  <h3 className="text-sm font-bold text-ncasa-text">Vendor Configuration Parsing Results</h3>
                </div>
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-status-pass-bg text-status-pass border border-status-pass/30">
                  PARSING COMPLETE
                </span>
              </div>

              {/* Parsing stats summary */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-ncasa-surface2 p-3 rounded border border-ncasa-border text-center">
                <div>
                  <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Total Files</p>
                  <p className="text-lg font-bold text-ncasa-text font-mono">{parsingSummary.total_files}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Parsed Files</p>
                  <p className="text-lg font-bold text-status-pass font-mono">{parsingSummary.parsed_files}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Unsupported</p>
                  <p className="text-lg font-bold text-amber-300 font-mono">{parsingSummary.unsupported_files}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Failed Files</p>
                  <p className="text-lg font-bold text-ncasa-muted font-mono">{parsingSummary.failed_files}</p>
                </div>
              </div>

              {/* Parsed files summary table */}
              <div className="border border-ncasa-border rounded overflow-hidden">
                <table className="w-full text-left text-xs">
                  <thead className="bg-ncasa-surface2 text-ncasa-muted border-b border-ncasa-border uppercase text-[10px]">
                    <tr>
                      <th className="p-2.5 font-semibold">File</th>
                      <th className="p-2.5 font-semibold">Vendor</th>
                      <th className="p-2.5 font-semibold">Device Type</th>
                      <th className="p-2.5 font-semibold">Parser</th>
                      <th className="p-2.5 font-semibold">Status</th>
                      <th className="p-2.5 font-semibold text-right">Structured Data</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-ncasa-border">
                    {(parsingSummary?.files || []).map((pfile) => {
                      const isExpanded = !!expandedParsedData[pfile.file_id];
                      const data = pfile.data || {};
                      const evidence = pfile.evidence || [];

                      return (
                        <React.Fragment key={pfile.file_id}>
                          <tr className="hover:bg-ncasa-surface2/50 transition-colors">
                            <td className="p-2.5 font-mono text-ncasa-text font-semibold">{pfile.file_id}</td>
                            <td className="p-2.5"><VendorBadge vendor={pfile.vendor} /></td>
                            <td className="p-2.5 font-semibold text-ncasa-text">{pfile.device_type}</td>
                            <td className="p-2.5 font-mono text-ncasa-accent font-semibold">{pfile.parser}</td>
                            <td className="p-2.5">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${pfile.status === 'PARSED' ? 'bg-status-pass-bg text-status-pass border border-status-pass/30' : 'bg-ncasa-surface2 text-ncasa-muted border border-ncasa-border'}`}>
                                {pfile.status === 'PARSED' ? 'Parsed' : 'Not Parsed'}
                              </span>
                            </td>
                            <td className="p-2.5 text-right">
                              {pfile.status === 'PARSED' ? (
                                <button
                                  onClick={() => toggleParsedData(pfile.file_id)}
                                  className="inline-flex items-center gap-1 text-xs text-ncasa-accent hover:underline font-medium"
                                >
                                  Inspect Data
                                  {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                                </button>
                              ) : (
                                <span className="text-ncasa-muted text-[11px] italic">No data</span>
                              )}
                            </td>
                          </tr>

                          {/* Expandable parsed configuration inspector */}
                          {isExpanded && (
                            <tr>
                              <td colSpan={6} className="bg-ncasa-surface2/80 p-4 border-b border-ncasa-border">
                                <div className="space-y-4 text-xs">
                                  <div className="flex items-center justify-between border-b border-ncasa-border pb-2">
                                    <p className="font-bold text-ncasa-text text-sm">
                                      Parsed Configuration Data — {pfile.file_id} ({pfile.parser})
                                    </p>
                                    <span className="text-[11px] font-mono text-ncasa-muted">
                                      {evidence.length} line-level evidence references recorded
                                    </span>
                                  </div>

                                  {/* Grid of structured extracted fields */}
                                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    {/* 1. Identity & Hostname */}
                                    <div className="bg-ncasa-surface border border-ncasa-border rounded p-3 space-y-1">
                                      <div className="flex items-center gap-1.5 text-ncasa-accent font-bold mb-1">
                                        <Server size={14} />
                                        <span>Identity & Hostname</span>
                                      </div>
                                      <p className="text-ncasa-subtle">
                                        Hostname: <span className="font-mono font-bold text-ncasa-text">{data.hostname || 'None'}</span>
                                      </p>
                                      {data.vdom && (
                                        <p className="text-ncasa-subtle">VDOM: <span className="font-mono font-bold text-ncasa-text">{data.vdom}</span></p>
                                      )}
                                    </div>

                                    {/* 2. Interfaces Summary */}
                                    <div className="bg-ncasa-surface border border-ncasa-border rounded p-3 space-y-1">
                                      <div className="flex items-center gap-1.5 text-ncasa-accent font-bold mb-1">
                                        <Globe size={14} />
                                        <span>Interfaces ({data.interfaces?.length || 0})</span>
                                      </div>
                                      {data.interfaces?.length > 0 ? (
                                        <div className="space-y-1 font-mono text-[11px]">
                                          {data.interfaces.slice(0, 4).map((iface, i) => (
                                            <div key={i} className="flex items-center justify-between text-ncasa-subtle border-b border-ncasa-border/50 pb-0.5">
                                              <span>{iface.name}</span>
                                              <span className="text-ncasa-muted">{iface.ip_addresses?.map((a) => a.ip || a).join(', ') || iface.ip || 'No IP'}</span>
                                            </div>
                                          ))}
                                          {data.interfaces.length > 4 && (
                                            <p className="text-[10px] text-ncasa-muted font-sans italic">
                                              + {data.interfaces.length - 4} more interface(s)
                                            </p>
                                          )}
                                        </div>
                                      ) : (
                                        <p className="text-ncasa-muted italic text-[11px]">No interfaces configured.</p>
                                      )}
                                    </div>

                                    {/* 3. Routing */}
                                    <div className="bg-ncasa-surface border border-ncasa-border rounded p-3 space-y-1">
                                      <div className="flex items-center gap-1.5 text-ncasa-accent font-bold mb-1">
                                        <Radio size={14} />
                                        <span>Routing Protocols</span>
                                      </div>
                                      <p className="text-ncasa-subtle">
                                        OSPF: <span className="font-mono font-bold text-ncasa-text">{data.routing?.ospf ? 'Configured' : 'None'}</span>
                                      </p>
                                      <p className="text-ncasa-subtle">
                                        BGP: <span className="font-mono font-bold text-ncasa-text">{data.routing?.bgp ? 'Configured' : 'None'}</span>
                                      </p>
                                      <p className="text-ncasa-subtle">
                                        Static Routes: <span className="font-mono font-bold text-ncasa-text">{data.routing?.static_routes?.length || data.static_routes?.length || 0}</span>
                                      </p>
                                    </div>

                                    {/* 4. Security / Management */}
                                    <div className="bg-ncasa-surface border border-ncasa-border rounded p-3 space-y-1">
                                      <div className="flex items-center gap-1.5 text-ncasa-accent font-bold mb-1">
                                        <Lock size={14} />
                                        <span>Management & Security</span>
                                      </div>
                                      <p className="text-ncasa-subtle">
                                        SSH: <span className="font-mono font-bold text-ncasa-text">{data.management?.ssh_version ? `v${data.management.ssh_version}` : data.management?.ssh_enabled ? 'Enabled' : 'Default'}</span>
                                      </p>
                                      <p className="text-ncasa-subtle">
                                        NTP Servers: <span className="font-mono font-bold text-ncasa-text">{data.ntp?.servers?.length || 0}</span>
                                      </p>
                                      <p className="text-ncasa-subtle">
                                        ACLs / Policies: <span className="font-mono font-bold text-ncasa-text">{data.acls?.length || data.firewall_policies?.length || data.security?.policies?.length || 0}</span>
                                      </p>
                                    </div>
                                  </div>

                                  {/* Line-level evidence drawer */}
                                  <div className="space-y-1.5">
                                    <p className="text-[10px] font-bold uppercase tracking-wider text-ncasa-muted">
                                      Line Evidence Traceability ({evidence.length} items)
                                    </p>
                                    <div className="max-h-40 overflow-y-auto space-y-1 font-mono text-[11px] bg-ncasa-surface p-2.5 rounded border border-ncasa-border">
                                      {evidence.map((ev, idx) => (
                                        <div key={idx} className="flex items-center justify-between text-ncasa-subtle border-b border-ncasa-border/40 pb-0.5">
                                          <div className="flex items-center gap-2">
                                            <span className="text-ncasa-accent font-bold">Line {ev.line}:</span>
                                            <span className="text-ncasa-muted">[{ev.field}]</span>
                                            <span className="text-ncasa-text">{ev.text}</span>
                                          </div>
                                          <span className="text-[9px] uppercase px-1 rounded bg-ncasa-surface2 text-ncasa-muted">
                                            {ev.source}
                                          </span>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {/* UNKNOWN vendor unparsed disclaimer banner */}
              {hasUnknownVendor && (
                <div className="flex items-start gap-3 p-3.5 rounded border border-amber-700/40 bg-amber-950/20 text-xs text-amber-200">
                  <HelpCircle size={18} className="text-amber-400 shrink-0 mt-0.5" />
                  <div>
                    <p className="font-semibold text-amber-300 mb-0.5">Not Parsed (Unknown Vendor)</p>
                    <p className="leading-relaxed">
                      Unknown vendor configurations are outside the deterministic parser set. AI-assisted configuration understanding will be introduced in Block 10.
                    </p>
                  </div>
                </div>
              )}

              {/* Action area: Trigger Vendor-Neutral Normalization (Block 6) */}
              {uploadState === STATE.PARSING_COMPLETE && (
                <div className="pt-2 flex items-center justify-between border-t border-ncasa-border mt-3">
                  <p className="text-xs text-ncasa-muted">
                    Next step: transform vendor-specific parsed configuration structures into a unified vendor-neutral security model.
                  </p>
                  <Button
                    variant="primary"
                    size="md"
                    onClick={handleRunNormalization}
                    icon={Layers}
                  >
                    Normalize Configurations
                  </Button>
                </div>
              )}

              {isNormalizing && (
                <div className="pt-2 flex items-center gap-3 text-sm text-ncasa-accent animate-pulse border-t border-ncasa-border mt-3">
                  <Loader2 size={18} className="animate-spin" />
                  <span>Transforming vendor configurations into vendor-neutral security model…</span>
                </div>
              )}

              <div className="pt-2 flex justify-between items-center">
                <Button variant="secondary" size="sm" icon={ClipboardList} onClick={handleReset}>
                  Start Another Audit
                </Button>
              </div>
            </div>
          )}

          {/* Card 5: Vendor-Neutral Configuration Normalization Results (Block 6) */}
          {normalizationSummary && (
            <div className="bg-ncasa-surface border border-ncasa-border rounded p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Layers size={18} className="text-ncasa-accent" />
                  <h3 className="text-sm font-bold text-ncasa-text">Vendor-Neutral Security Model Normalization Results</h3>
                </div>
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-status-pass-bg text-status-pass border border-status-pass/30">
                  NORMALIZATION COMPLETE
                </span>
              </div>

              {/* Normalization stats summary */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-ncasa-surface2 p-3 rounded border border-ncasa-border text-center">
                <div>
                  <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Total Files</p>
                  <p className="text-lg font-bold text-ncasa-text font-mono">{normalizationSummary.total_files}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Normalized Files</p>
                  <p className="text-lg font-bold text-status-pass font-mono">{normalizationSummary.normalized_files}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Unsupported</p>
                  <p className="text-lg font-bold text-amber-300 font-mono">{normalizationSummary.unsupported_files}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Failed Files</p>
                  <p className="text-lg font-bold text-ncasa-muted font-mono">{normalizationSummary.failed_files}</p>
                </div>
              </div>

              {/* Normalized files summary table */}
              <div className="border border-ncasa-border rounded overflow-hidden">
                <table className="w-full text-left text-xs">
                  <thead className="bg-ncasa-surface2 text-ncasa-muted border-b border-ncasa-border uppercase text-[10px]">
                    <tr>
                      <th className="p-2.5 font-semibold">File</th>
                      <th className="p-2.5 font-semibold">Vendor</th>
                      <th className="p-2.5 font-semibold">Device Type</th>
                      <th className="p-2.5 font-semibold">Normalizer</th>
                      <th className="p-2.5 font-semibold">Status</th>
                      <th className="p-2.5 font-semibold text-right">Vendor-Neutral Model</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-ncasa-border">
                    {(normalizationSummary?.files || []).map((nfile) => {
                      const isExpanded = !!expandedNormalizedData[nfile.file_id];
                      const data = nfile;
                      const evidence = nfile.evidence || [];

                      return (
                        <React.Fragment key={nfile.file_id}>
                          <tr className="hover:bg-ncasa-surface2/50 transition-colors">
                            <td className="p-2.5 font-mono text-ncasa-text font-semibold">{nfile.file_id}</td>
                            <td className="p-2.5"><VendorBadge vendor={nfile.vendor} /></td>
                            <td className="p-2.5 font-semibold text-ncasa-text">{nfile.device_type}</td>
                            <td className="p-2.5 font-mono text-ncasa-accent font-semibold">{nfile.normalizer}</td>
                            <td className="p-2.5">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${nfile.status === 'NORMALIZED' ? 'bg-status-pass-bg text-status-pass border border-status-pass/30' : 'bg-ncasa-surface2 text-ncasa-muted border border-ncasa-border'}`}>
                                {nfile.status === 'NORMALIZED' ? 'Normalized' : nfile.status}
                              </span>
                            </td>
                            <td className="p-2.5 text-right">
                              {nfile.status === 'NORMALIZED' ? (
                                <button
                                  onClick={() => toggleNormalizedData(nfile.file_id)}
                                  className="inline-flex items-center gap-1 text-xs text-ncasa-accent hover:underline font-medium"
                                >
                                  Inspect Security Model
                                  {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                                </button>
                              ) : (
                                <span className="text-ncasa-muted text-[11px] italic">Not Supported</span>
                              )}
                            </td>
                          </tr>

                          {/* Expandable Vendor-Neutral Security Model Inspector */}
                          {isExpanded && (
                            <tr>
                              <td colSpan={6} className="bg-ncasa-surface2/80 p-4 border-b border-ncasa-border">
                                <div className="space-y-4 text-xs">
                                  <div className="flex items-center justify-between border-b border-ncasa-border pb-2">
                                    <p className="font-bold text-ncasa-text text-sm">
                                      Vendor-Neutral Security Model — {nfile.file_id} ({nfile.normalizer})
                                    </p>
                                    <span className="text-[11px] font-mono text-ncasa-muted">
                                      {evidence.length} trace evidence items retained
                                    </span>
                                  </div>

                                  {/* Grid of normalized security domains */}
                                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    {/* 1. Identity & System */}
                                    <div className="bg-ncasa-surface border border-ncasa-border rounded p-3 space-y-1">
                                      <div className="flex items-center gap-1.5 text-ncasa-accent font-bold mb-1">
                                        <Server size={14} />
                                        <span>Normalized Identity</span>
                                      </div>
                                      <p className="text-ncasa-subtle">
                                        Hostname: <span className="font-mono font-bold text-ncasa-text">{data.identity?.hostname || 'None'}</span>
                                      </p>
                                      <p className="text-ncasa-subtle">
                                        Domain: <span className="font-mono font-bold text-ncasa-text">{data.identity?.domain_name || 'None'}</span>
                                      </p>
                                    </div>

                                    {/* 2. Management Security */}
                                    <div className="bg-ncasa-surface border border-ncasa-border rounded p-3 space-y-1">
                                      <div className="flex items-center gap-1.5 text-ncasa-accent font-bold mb-1">
                                        <Lock size={14} />
                                        <span>Management Security</span>
                                      </div>
                                      <p className="text-ncasa-subtle">
                                        SSH: <span className="font-mono font-bold text-ncasa-text">{data.management?.ssh?.enabled ? `Enabled (v${data.management.ssh.version || '2'})` : 'Disabled / Default'}</span>
                                      </p>
                                      <p className="text-ncasa-subtle">
                                        Telnet: <span className="font-mono font-bold text-ncasa-text">{data.management?.telnet?.enabled === false ? 'Disabled' : data.management?.telnet?.enabled === true ? 'ENABLED (Insecure)' : 'Unverified'}</span>
                                      </p>
                                      <p className="text-ncasa-subtle">
                                        HTTPS / HTTP: <span className="font-mono font-bold text-ncasa-text">{data.management?.https?.enabled ? 'HTTPS Enabled' : 'HTTPS Default'} / {data.management?.http?.enabled ? 'HTTP Enabled' : 'HTTP Default'}</span>
                                      </p>
                                    </div>

                                    {/* 3. Authentication & AAA */}
                                    <div className="bg-ncasa-surface border border-ncasa-border rounded p-3 space-y-1">
                                      <div className="flex items-center gap-1.5 text-ncasa-accent font-bold mb-1">
                                        <Shield size={14} />
                                        <span>AAA & Credentials</span>
                                      </div>
                                      <p className="text-ncasa-subtle">
                                        Enable Secret: <span className="font-mono font-bold text-ncasa-text">{data.authentication?.enable_secret_present ? 'Present (Encrypted)' : 'Absent'}</span>
                                      </p>
                                      <p className="text-ncasa-subtle">
                                        Local Users: <span className="font-mono font-bold text-ncasa-text">{data.authentication?.usernames?.length || 0} configured</span>
                                      </p>
                                      <p className="text-ncasa-subtle">
                                        AAA Model: <span className="font-mono font-bold text-ncasa-text">{data.authentication?.aaa_new_model ? 'Configured' : 'None'}</span>
                                      </p>
                                    </div>

                                    {/* 4. Interfaces & Netmask-to-CIDR */}
                                    <div className="bg-ncasa-surface border border-ncasa-border rounded p-3 space-y-1">
                                      <div className="flex items-center gap-1.5 text-ncasa-accent font-bold mb-1">
                                        <Globe size={14} />
                                        <span>Normalized Interfaces ({data.interfaces?.length || 0})</span>
                                      </div>
                                      {data.interfaces?.length > 0 ? (
                                        <div className="space-y-1 font-mono text-[11px]">
                                          {data.interfaces.slice(0, 4).map((iface, i) => (
                                            <div key={i} className="flex items-center justify-between text-ncasa-subtle border-b border-ncasa-border/50 pb-0.5">
                                              <span>{iface.name}</span>
                                              <span className="text-ncasa-accent font-bold">{iface.ip_addresses?.join(', ') || 'No IP'}</span>
                                            </div>
                                          ))}
                                          {data.interfaces.length > 4 && (
                                            <p className="text-[10px] text-ncasa-muted font-sans italic">
                                              + {data.interfaces.length - 4} more interface(s)
                                            </p>
                                          )}
                                        </div>
                                      ) : (
                                        <p className="text-ncasa-muted italic text-[11px]">No interfaces configured.</p>
                                      )}
                                    </div>

                                    {/* 5. Firewall Policies & Security Zones */}
                                    <div className="bg-ncasa-surface border border-ncasa-border rounded p-3 space-y-1">
                                      <div className="flex items-center gap-1.5 text-ncasa-accent font-bold mb-1">
                                        <Radio size={14} />
                                        <span>Firewall Policies & Zones</span>
                                      </div>
                                      <p className="text-ncasa-subtle">
                                        Security Zones: <span className="font-mono font-bold text-ncasa-text">{data.security_zones?.length || 0}</span>
                                      </p>
                                      <p className="text-ncasa-subtle">
                                        Policies / ACLs: <span className="font-mono font-bold text-ncasa-text">{data.firewall_policies?.length || data.acls?.length || 0}</span>
                                      </p>
                                    </div>

                                    {/* 6. Logging & NTP */}
                                    <div className="bg-ncasa-surface border border-ncasa-border rounded p-3 space-y-1">
                                      <div className="flex items-center gap-1.5 text-ncasa-accent font-bold mb-1">
                                        <FileText size={14} />
                                        <span>Logging & NTP</span>
                                      </div>
                                      <p className="text-ncasa-subtle">
                                        Remote Logging: <span className="font-mono font-bold text-ncasa-text">{data.logging?.remote_servers?.join(', ') || 'None'}</span>
                                      </p>
                                      <p className="text-ncasa-subtle">
                                        NTP Servers: <span className="font-mono font-bold text-ncasa-text">{data.ntp?.servers?.join(', ') || 'None'}</span>
                                      </p>
                                    </div>
                                  </div>

                                  {/* Line Evidence Traceability */}
                                  <div className="space-y-1.5">
                                    <p className="text-[10px] font-bold uppercase tracking-wider text-ncasa-muted">
                                      Normalized Source Evidence Chain ({evidence.length} items)
                                    </p>
                                    <div className="max-h-40 overflow-y-auto space-y-1 font-mono text-[11px] bg-ncasa-surface p-2.5 rounded border border-ncasa-border">
                                      {evidence.map((ev, idx) => (
                                        <div key={idx} className="flex items-center justify-between text-ncasa-subtle border-b border-ncasa-border/40 pb-0.5">
                                          <div className="flex items-center gap-2">
                                            <span className="text-ncasa-accent font-bold">Line {ev.source_line}:</span>
                                            <span className="text-ncasa-muted">[{ev.field}]</span>
                                            <span className="text-ncasa-text">{ev.source_text}</span>
                                          </div>
                                          <span className="text-[9px] uppercase px-1 rounded bg-ncasa-surface2 text-ncasa-muted">
                                            {ev.source_vendor}
                                          </span>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {/* Action area: Trigger Deterministic Compliance Audit (Block 7) */}
              {uploadState === STATE.NORMALIZATION_COMPLETE && (
                <div className="pt-2 flex items-center justify-between border-t border-ncasa-border mt-3">
                  <p className="text-xs text-ncasa-muted">
                    Next step: evaluate normalized configuration models against deterministic security control rules.
                  </p>
                  <Button
                    variant="primary"
                    size="md"
                    onClick={handleRunCompliance}
                    icon={Shield}
                  >
                    Run Compliance Audit
                  </Button>
                </div>
              )}

              {isEvaluatingCompliance && (
                <div className="pt-2 flex items-center gap-3 text-sm text-ncasa-accent animate-pulse border-t border-ncasa-border mt-3">
                  <Loader2 size={18} className="animate-spin" />
                  <span>Evaluating normalized configurations against rule-based security controls…</span>
                </div>
              )}
            </div>
          )}

          {/* Card 6: Deterministic Compliance Audit Results (Block 7) */}
          {complianceSummary && (
            <div className="bg-ncasa-surface border border-ncasa-border rounded p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Shield size={18} className="text-ncasa-accent" />
                  <h3 className="text-sm font-bold text-ncasa-text">Deterministic Compliance Audit Results</h3>
                </div>
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-status-pass-bg text-status-pass border border-status-pass/30">
                  COMPLIANCE COMPLETE
                </span>
              </div>

              {/* Top summary cards grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-ncasa-surface2 p-3 rounded border border-ncasa-border text-center">
                <div>
                  <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Total Controls</p>
                  <p className="text-xl font-bold text-ncasa-text font-mono">{complianceSummary?.summary?.total_controls ?? complianceSummary?.total_controls ?? 0}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Passed Controls</p>
                  <p className="text-xl font-bold text-status-pass font-mono">{complianceSummary?.summary?.passed ?? complianceSummary?.passed ?? 0}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Failed Controls</p>
                  <p className="text-xl font-bold text-sev-critical font-mono">{complianceSummary?.summary?.failed ?? complianceSummary?.failed ?? 0}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Not Verifiable</p>
                  <p className="text-xl font-bold text-amber-300 font-mono">{complianceSummary?.summary?.not_verifiable ?? complianceSummary?.not_verifiable ?? 0}</p>
                </div>
              </div>

              {/* Filters bar */}
              <div className="flex flex-wrap items-center justify-between gap-3 bg-ncasa-surface p-3 rounded border border-ncasa-border text-xs">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-ncasa-muted">Framework Filter:</span>
                  {['ALL', 'CIS', 'NIST', 'STIG'].map((fw) => (
                    <button
                      key={fw}
                      onClick={() => setCompFrameworkFilter(fw)}
                      className={`px-2.5 py-1 rounded text-[11px] font-semibold transition-colors ${
                        compFrameworkFilter === fw
                          ? 'bg-ncasa-accent text-white font-bold'
                          : 'bg-ncasa-surface2 text-ncasa-subtle hover:bg-ncasa-border'
                      }`}
                    >
                      {fw}
                    </button>
                  ))}
                </div>

                <div className="flex items-center gap-2">
                  <span className="font-semibold text-ncasa-muted">Severity Filter:</span>
                  {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
                    <button
                      key={sev}
                      onClick={() => setCompSeverityFilter(sev)}
                      className={`px-2.5 py-1 rounded text-[11px] font-semibold transition-colors ${
                        compSeverityFilter === sev
                          ? 'bg-ncasa-accent text-white font-bold'
                          : 'bg-ncasa-surface2 text-ncasa-subtle hover:bg-ncasa-border'
                      }`}
                    >
                      {sev}
                    </button>
                  ))}
                </div>
              </div>

              {/* Results table */}
              <div className="border border-ncasa-border rounded overflow-hidden">
                <table className="w-full text-left text-xs">
                  <thead className="bg-ncasa-surface2 text-ncasa-muted border-b border-ncasa-border uppercase text-[10px]">
                    <tr>
                      <th className="p-2.5 font-semibold">Control ID</th>
                      <th className="p-2.5 font-semibold">Framework</th>
                      <th className="p-2.5 font-semibold">Title / Category</th>
                      <th className="p-2.5 font-semibold">Severity</th>
                      <th className="p-2.5 font-semibold">Compliance Status</th>
                      <th className="p-2.5 font-semibold text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-ncasa-border">
                    {(complianceSummary?.results || [])
                      .filter((c) => compFrameworkFilter === 'ALL' || (c.framework || '').toUpperCase() === compFrameworkFilter)
                      .filter((c) => compSeverityFilter === 'ALL' || (c.severity || '').toUpperCase() === compSeverityFilter)
                      .map((cres) => {
                        const isExpanded = !!expandedControlData[cres.control_id];
                        const statusClass =
                          cres.status === 'PASS'
                            ? 'bg-status-pass-bg text-status-pass border-status-pass/30'
                            : cres.status === 'FAIL'
                            ? 'bg-sev-critical-bg text-sev-critical border-sev-critical/30'
                            : 'bg-amber-950/40 text-amber-300 border-amber-700/40';

                        const sevClass =
                          cres.severity === 'HIGH' || cres.severity === 'CRITICAL'
                            ? 'bg-red-900/30 text-red-300 border-red-700/40'
                            : cres.severity === 'MEDIUM'
                            ? 'bg-amber-900/30 text-amber-300 border-amber-700/40'
                            : 'bg-blue-900/30 text-blue-300 border-blue-700/40';

                        return (
                          <React.Fragment key={cres.control_id}>
                            <tr className="hover:bg-ncasa-surface2/50 transition-colors">
                              <td className="p-2.5 font-mono text-ncasa-accent font-bold">
                                {cres.control_id}
                                <span className="ml-1 text-[9px] px-1 py-0.2 rounded bg-ncasa-surface2 text-ncasa-muted border border-ncasa-border font-sans font-normal">
                                  Internal Mapping
                                </span>
                              </td>
                              <td className="p-2.5 font-semibold text-ncasa-text">{cres.framework}</td>
                              <td className="p-2.5">
                                <p className="font-semibold text-ncasa-text">{cres.title}</p>
                                <p className="text-[10px] text-ncasa-muted">{cres.category}</p>
                              </td>
                              <td className="p-2.5">
                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${sevClass}`}>
                                  {cres.severity}
                                </span>
                              </td>
                              <td className="p-2.5">
                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${statusClass}`}>
                                  {cres.status === 'NOT_VERIFIABLE' ? 'NOT VERIFIABLE' : cres.status}
                                </span>
                              </td>
                              <td className="p-2.5 text-right">
                                <button
                                  onClick={() => toggleControlData(cres.control_id)}
                                  className="inline-flex items-center gap-1 text-xs text-ncasa-accent hover:underline font-medium"
                                >
                                  View Audit Details
                                  {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                                </button>
                              </td>
                            </tr>

                            {/* Expandable Control Detail Panel */}
                            {isExpanded && (
                              <tr>
                                <td colSpan={6} className="bg-ncasa-surface2/80 p-4 border-b border-ncasa-border">
                                  <div className="space-y-4 text-xs">
                                    <div className="flex items-center justify-between border-b border-ncasa-border pb-2">
                                      <div>
                                        <p className="font-bold text-ncasa-text text-sm">
                                          {cres.control_id} — {cres.title}
                                        </p>
                                        <p className="text-xs text-ncasa-muted mt-0.5">{cres.description}</p>
                                      </div>
                                      <span className={`px-2.5 py-1 rounded text-xs font-bold border ${statusClass}`}>
                                        {cres.status === 'NOT_VERIFIABLE' ? 'NOT VERIFIABLE' : cres.status}
                                      </span>
                                    </div>

                                    {/* Expected vs Observed */}
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                      <div className="bg-ncasa-surface border border-ncasa-border rounded p-3 space-y-1">
                                        <p className="text-[10px] font-bold uppercase tracking-wider text-ncasa-accent">
                                          Expected Control Requirement
                                        </p>
                                        <p className="text-ncasa-text leading-relaxed font-medium">{cres.expected}</p>
                                      </div>

                                      <div className="bg-ncasa-surface border border-ncasa-border rounded p-3 space-y-1">
                                        <p className="text-[10px] font-bold uppercase tracking-wider text-ncasa-subtle">
                                          Observed Configuration State
                                        </p>
                                        <p className="text-ncasa-text leading-relaxed font-mono text-[11px]">{cres.observed}</p>
                                      </div>
                                    </div>

                                    {/* Deterministic Explanation */}
                                    {cres.explanation && (
                                      <div className="bg-ncasa-surface border border-ncasa-border rounded p-3 space-y-1">
                                        <p className="text-[10px] font-bold uppercase tracking-wider text-ncasa-muted">
                                          Deterministic Compliance Rationale
                                        </p>
                                        <p className="text-ncasa-subtle leading-relaxed">{cres.explanation}</p>
                                      </div>
                                    )}

                                    {/* Line Evidence Chain */}
                                    <div className="space-y-1.5">
                                      <p className="text-[10px] font-bold uppercase tracking-wider text-ncasa-muted">
                                        Supporting Evidence Chain ({cres.evidence?.length || 0} items)
                                      </p>
                                      {cres.evidence && cres.evidence.length > 0 ? (
                                        <div className="max-h-40 overflow-y-auto space-y-1 font-mono text-[11px] bg-ncasa-surface p-2.5 rounded border border-ncasa-border">
                                          {cres.evidence.map((ev, idx) => (
                                            <div key={idx} className="flex items-center justify-between text-ncasa-subtle border-b border-ncasa-border/40 pb-0.5">
                                              <div className="flex items-center gap-2">
                                                <span className="text-ncasa-accent font-bold">{ev.source_file} (Line {ev.source_line}):</span>
                                                <span className="text-ncasa-muted">[{ev.field}]</span>
                                                <span className="text-ncasa-text">{ev.source_text}</span>
                                              </div>
                                            </div>
                                          ))}
                                        </div>
                                      ) : (
                                        <p className="text-ncasa-muted italic text-[11px] bg-ncasa-surface p-2 rounded border border-ncasa-border">
                                          No line-level configuration evidence available for this control state.
                                        </p>
                                      )}
                                    </div>
                                  </div>
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        );
                      })}
                  </tbody>
                </table>
              </div>

              {/* Action area: Trigger Findings Engine (Block 8) */}
              {uploadState === STATE.COMPLIANCE_COMPLETE && (
                <div className="pt-2 flex items-center justify-between border-t border-ncasa-border mt-3">
                  <p className="text-xs text-ncasa-muted">
                    Next step: extract deduplicated security findings and assessment limitations from compliance results.
                  </p>
                  <Button
                    variant="primary"
                    size="md"
                    onClick={handleGenerateFindings}
                    icon={AlertTriangle}
                  >
                    Generate Security Findings
                  </Button>
                </div>
              )}

              {isGeneratingFindings && (
                <div className="pt-2 flex items-center gap-3 text-sm text-ncasa-accent animate-pulse border-t border-ncasa-border mt-3">
                  <Loader2 size={18} className="animate-spin" />
                  <span>Extracting actionable security findings and assessment limitations…</span>
                </div>
              )}
            </div>
          )}

          {/* Card 7: Security Findings & Risk Classification Results (Block 8) */}
          {findingsSummary && (
            <div className="bg-ncasa-surface border border-ncasa-border rounded p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <AlertTriangle size={18} className="text-ncasa-accent" />
                  <h3 className="text-sm font-bold text-ncasa-text">Security Findings & Risk Classification Results</h3>
                </div>
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-status-pass-bg text-status-pass border border-status-pass/30">
                  FINDINGS COMPLETE
                </span>
              </div>

              {/* Summary stats grid */}
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 bg-ncasa-surface2 p-3 rounded border border-ncasa-border text-center">
                <div>
                  <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Total Findings</p>
                  <p className="text-xl font-bold text-ncasa-text font-mono">{findingsSummary.summary?.total_findings || 0}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Critical</p>
                  <p className="text-xl font-bold text-sev-critical font-mono">{findingsSummary.summary?.critical || 0}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase font-semibold text-ncasa-muted">High</p>
                  <p className="text-xl font-bold text-sev-high font-mono">{findingsSummary.summary?.high || 0}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Medium</p>
                  <p className="text-xl font-bold text-sev-medium font-mono">{findingsSummary.summary?.medium || 0}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Limitations</p>
                  <p className="text-xl font-bold text-ncasa-accent font-mono">{findingsSummary.summary?.assessment_limitations || 0}</p>
                </div>
              </div>

              {/* Findings table preview */}
              {(findingsSummary.findings || []).length > 0 ? (
                <div className="border border-ncasa-border rounded overflow-hidden">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-ncasa-surface2 text-ncasa-muted border-b border-ncasa-border uppercase text-[10px]">
                      <tr>
                        <th className="p-2.5 font-semibold">Finding ID</th>
                        <th className="p-2.5 font-semibold">Severity</th>
                        <th className="p-2.5 font-semibold">Title</th>
                        <th className="p-2.5 font-semibold">Category</th>
                        <th className="p-2.5 font-semibold">Affected Files</th>
                        <th className="p-2.5 font-semibold">Remediation</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-ncasa-border">
                      {(findingsSummary?.findings || []).map((f) => (
                        <tr key={f.finding_id} className="hover:bg-ncasa-surface2/50 transition-colors">
                          <td className="p-2.5 font-mono text-ncasa-accent font-bold">{f.finding_id}</td>
                          <td className="p-2.5"><Badge label={f.severity} type="severity" /></td>
                          <td className="p-2.5 font-semibold text-ncasa-text">{f.title}</td>
                          <td className="p-2.5 text-ncasa-subtle">{f.category}</td>
                          <td className="p-2.5 font-mono text-ncasa-muted">{(f.affected_files || []).length} files</td>
                          <td className="p-2.5">
                            <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-ncasa-surface2 text-ncasa-muted border border-ncasa-border">
                              {f.remediation_status}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="p-4 bg-ncasa-surface2 rounded border border-ncasa-border text-center text-xs text-ncasa-muted">
                  No actionable compliance failures detected. All evaluated controls passed!
                </div>
              )}

              {/* Action area */}
              <div className="pt-2 flex justify-between items-center">
                <Button variant="secondary" size="sm" icon={ClipboardList} onClick={handleReset}>
                  Start Another Audit
                </Button>
                <a href="/findings" className="inline-flex items-center gap-1.5 text-xs text-ncasa-accent hover:underline font-semibold">
                  View Full Findings Dashboard →
                </a>
              </div>

              {/* Action area: Trigger Remediation Engine (Block 9) */}
              {uploadState === STATE.FINDINGS_COMPLETE && (
                <div className="pt-2 flex items-center justify-between border-t border-ncasa-border mt-3">
                  <p className="text-xs text-ncasa-muted">
                    Next step: generate vendor-specific, human-reviewable proposed configuration changes.
                  </p>
                  <Button
                    variant="primary"
                    size="md"
                    onClick={handleGenerateRemediation}
                    icon={FileCode}
                  >
                    Generate Remediation Proposals
                  </Button>
                </div>
              )}

              {isGeneratingRemediation && (
                <div className="pt-2 flex items-center gap-3 text-sm text-ncasa-accent animate-pulse border-t border-ncasa-border mt-3">
                  <Loader2 size={18} className="animate-spin" />
                  <span>Generating vendor-specific proposed configuration fixes…</span>
                </div>
              )}
            </div>
          )}

          {/* Card 8: Remediation Proposals Results (Block 9) */}
          {remediationSummary && (
            <div className="bg-ncasa-surface border border-ncasa-border rounded p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileCode size={18} className="text-ncasa-accent" />
                  <h3 className="text-sm font-bold text-ncasa-text">Vendor Remediation Proposals</h3>
                </div>
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-status-pass-bg text-status-pass border border-status-pass/30">
                  REMEDIATION COMPLETE
                </span>
              </div>

              {/* Summary stats grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-ncasa-surface2 p-3 rounded border border-ncasa-border text-center">
                <div>
                  <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Total Findings</p>
                  <p className="text-xl font-bold text-ncasa-text font-mono">{remediationSummary.summary?.total_findings || 0}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Proposals Available</p>
                  <p className="text-xl font-bold text-status-pass font-mono">{remediationSummary.summary?.remediations_available || 0}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Manual Review Required</p>
                  <p className="text-xl font-bold text-amber-300 font-mono">{remediationSummary.summary?.manual_review_required || 0}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase font-semibold text-ncasa-muted">Reviewed by Admin</p>
                  <p className="text-xl font-bold text-blue-300 font-mono">{remediationSummary.summary?.reviewed || 0}</p>
                </div>
              </div>

              {/* Remediation table preview */}
              {(remediationSummary.remediations || []).length > 0 ? (
                <div className="border border-ncasa-border rounded overflow-hidden">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-ncasa-surface2 text-ncasa-muted border-b border-ncasa-border uppercase text-[10px]">
                      <tr>
                        <th className="p-2.5 font-semibold">Remediation ID</th>
                        <th className="p-2.5 font-semibold">Vendor</th>
                        <th className="p-2.5 font-semibold">Control</th>
                        <th className="p-2.5 font-semibold">Status</th>
                        <th className="p-2.5 font-semibold">Proposed Commands</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-ncasa-border">
                      {(remediationSummary?.remediations || []).map((r) => (
                        <tr key={r.remediation_id} className="hover:bg-ncasa-surface2/50 transition-colors">
                          <td className="p-2.5 font-mono text-ncasa-accent font-bold">{r.remediation_id}</td>
                          <td className="p-2.5"><VendorBadge vendor={r.vendor} /></td>
                          <td className="p-2.5 font-mono text-ncasa-subtle">{r.control_id}</td>
                          <td className="p-2.5">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              r.status === 'AVAILABLE'
                                ? 'bg-status-pass-bg text-status-pass border border-status-pass/30'
                                : 'bg-amber-950/40 text-amber-300 border border-amber-700/40'
                            }`}>
                              {r.status}
                            </span>
                          </td>
                          <td className="p-2.5 font-mono text-ncasa-subtle">
                            {(r.proposed_commands || []).length > 0
                              ? r.proposed_commands.join('; ')
                              : <span className="text-amber-300 italic">Manual operator review required</span>}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="p-4 bg-ncasa-surface2 rounded border border-ncasa-border text-center text-xs text-ncasa-muted">
                  No open findings requiring remediation proposals.
                </div>
              )}

              {/* Action area */}
              <div className="pt-2 flex justify-between items-center flex-wrap gap-2">
                <Button variant="secondary" size="sm" icon={ClipboardList} onClick={handleReset}>
                  Start Another Audit
                </Button>
                <div className="flex items-center gap-3">
                  {hasUnknownVendor ? (
                    <Button
                      variant="primary"
                      size="sm"
                      icon={Sparkles}
                      onClick={handleRunAiAnalysis}
                      disabled={isAnalyzingAi}
                    >
                      {isAnalyzingAi ? 'Running AI Analysis…' : 'Run AI Analysis (Unknown Vendors)'}
                    </Button>
                  ) : (
                    <Button
                      variant="primary"
                      size="sm"
                      icon={FileText}
                      onClick={handleGenerateReportSnapshot}
                      disabled={isGeneratingReport}
                    >
                      {isGeneratingReport ? 'Generating Report…' : 'Generate Audit Report'}
                    </Button>
                  )}
                  <a href="/remediation" className="inline-flex items-center gap-1.5 text-xs text-ncasa-accent hover:underline font-semibold">
                    Review Proposals Dashboard →
                  </a>
                </div>
              </div>
            </div>
          )}

          {/* Card 9: AI Analysis Results / Status (Block 10) */}
          {auditData && (
            <div className="bg-ncasa-surface border border-ncasa-border rounded p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Sparkles size={18} className="text-ncasa-accent" />
                  <h3 className="text-sm font-bold text-ncasa-text">AI-Assisted Configuration Understanding</h3>
                </div>
                <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${
                  !hasUnknownVendor
                    ? 'bg-ncasa-surface2 text-ncasa-muted border border-ncasa-border'
                    : aiAnalysisSummary
                    ? 'bg-status-pass-bg text-status-pass border border-status-pass/30'
                    : 'bg-amber-950/40 text-amber-300 border border-amber-700/40'
                }`}>
                  {!hasUnknownVendor ? 'NOT REQUIRED' : aiAnalysisSummary ? 'AI ANALYSIS COMPLETE' : 'AVAILABLE'}
                </span>
              </div>

              {!hasUnknownVendor ? (
                <div className="p-3.5 bg-ncasa-surface2 rounded border border-ncasa-border text-xs text-ncasa-muted leading-relaxed">
                  <span className="font-semibold text-ncasa-subtle">Deterministic Parsing Enforcement:</span> All configuration files in this audit belong to known vendors (Cisco, Juniper, Fortinet) and were parsed deterministically. AI analysis is reserved for unknown configuration syntaxes and was not required.
                </div>
              ) : aiAnalysisSummary ? (
                <div className="bg-ncasa-surface2 p-4 rounded border border-ncasa-border space-y-3 text-xs">
                  <div className="flex items-center justify-between border-b border-ncasa-border pb-2">
                    <span className="font-bold text-ncasa-text">AI Configuration Understanding Summary</span>
                    <span className="font-mono text-ncasa-accent font-bold">Status: {aiAnalysisSummary.status}</span>
                  </div>
                  <div className="space-y-1">
                    <p className="font-semibold text-ncasa-subtle">Analyzed Configurations:</p>
                    <p className="font-mono text-ncasa-muted text-[11px]">{aiAnalysisSummary.files?.map((f) => f.filename).join(', ')}</p>
                  </div>
                </div>
              ) : (
                <div className="flex items-center justify-between p-3.5 bg-amber-950/20 border border-amber-500/30 rounded text-xs">
                  <span className="text-amber-300 font-medium">Unknown vendor configurations detected. Trigger AI analysis for syntax understanding.</span>
                  <Button variant="primary" size="sm" icon={Sparkles} onClick={handleRunAiAnalysis} disabled={isAnalyzingAi}>
                    {isAnalyzingAi ? 'Analyzing…' : 'Run AI Analysis'}
                  </Button>
                </div>
              )}
            </div>
          )}

          {/* Card 10: Persistent Report Generation (Block 12) */}
          {auditData && (
            <div className="bg-ncasa-surface border border-ncasa-border rounded p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileText size={18} className="text-ncasa-accent" />
                  <h3 className="text-sm font-bold text-ncasa-text">Security Audit Report Snapshot</h3>
                </div>
                <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${
                  reportMetadata
                    ? 'bg-status-pass-bg text-status-pass border border-status-pass/30'
                    : 'bg-ncasa-surface2 text-ncasa-muted border border-ncasa-border'
                }`}>
                  {reportMetadata ? 'REPORT READY' : 'SNAPSHOT PENDING'}
                </span>
              </div>

              {reportMetadata ? (
                <div className="bg-ncasa-surface2 p-4 rounded border border-ncasa-border space-y-3 text-xs">
                  <div className="flex items-center justify-between border-b border-ncasa-border pb-2">
                    <div>
                      <p className="font-mono text-xs font-bold text-ncasa-accent">Report ID: {reportMetadata.report_id}</p>
                      <p className="text-[10px] text-ncasa-muted">Generated: {new Date(reportMetadata.generated_at).toLocaleString()}</p>
                    </div>
                    <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-ncasa-surface text-ncasa-subtle border border-ncasa-border">
                      v{reportMetadata.report_version}
                    </span>
                  </div>

                  <div className="flex items-center gap-3 pt-1">
                    <a
                      href={getReportHtmlUrl(auditData.audit_id, reportMetadata.report_id)}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold bg-ncasa-accent text-white hover:bg-ncasa-accent/90 transition-colors"
                    >
                      <Eye size={14} /> View HTML Report
                    </a>
                    <a
                      href={getReportPdfUrl(auditData.audit_id, reportMetadata.report_id)}
                      target="_blank"
                      rel="noreferrer"
                      download={`N-CASA-${reportMetadata.report_id}.pdf`}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold bg-status-pass text-ncasa-bg hover:opacity-90 transition-opacity"
                    >
                      <Download size={14} /> Download PDF Report
                    </a>
                  </div>
                </div>
              ) : (
                <div className="flex items-center justify-between p-3.5 bg-ncasa-surface2 border border-ncasa-border rounded text-xs">
                  <span className="text-ncasa-muted">Generate a persistent point-in-time HTML and PDF audit report snapshot.</span>
                  <Button
                    variant="primary"
                    size="sm"
                    icon={FileText}
                    onClick={handleGenerateReportSnapshot}
                    disabled={isGeneratingReport}
                  >
                    {isGeneratingReport ? 'Generating Snapshot…' : 'Generate Report Snapshot'}
                  </Button>
                </div>
              )}
            </div>
          )}
        </div>
      )}


      {/* ── UPLOAD FORM (hidden once post-upload flow is active) ─────────────── */}
      {!isPostUpload && (
        <>
          {/* Step 1: Upload */}
          <div className="bg-ncasa-surface border border-ncasa-border rounded p-5 space-y-4">
            <div className="flex items-center gap-2 mb-1">
              <span className="flex items-center justify-center w-5 h-5 rounded-full bg-ncasa-accent text-white text-[10px] font-bold shrink-0">1</span>
              <p className="text-sm font-semibold text-ncasa-text">Upload Configuration</p>
            </div>
            <p className="text-xs text-ncasa-muted">
              Supported formats:{' '}
              {ACCEPTED_EXTENSIONS.map((e) => (
                <span key={e} className="font-mono font-semibold text-ncasa-subtle bg-ncasa-surface2 px-1 py-0.5 rounded mx-0.5 text-[11px]">
                  {e.toUpperCase()}
                </span>
              ))}
              <span className="ml-2 text-ncasa-muted">· Max 50 MB</span>
            </p>

            {/* ── EMPTY drop zone ─────────────────────────── */}
            {uploadState === STATE.EMPTY && (
              <div
                onDrop={handleDrop}
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onClick={handleBrowse}
                className={`
                  relative flex flex-col items-center justify-center
                  border-2 border-dashed rounded-lg py-12 px-6 text-center
                  transition-colors duration-150 cursor-pointer
                  ${dragging
                    ? 'border-ncasa-accent bg-ncasa-accent-l/20'
                    : 'border-ncasa-border hover:border-ncasa-border2 hover:bg-ncasa-surface2'
                  }
                `}
              >
                <UploadCloud size={36} className={`mb-3 ${dragging ? 'text-ncasa-accent' : 'text-ncasa-muted'}`} />
                <p className="text-sm text-ncasa-subtle font-medium">
                  {dragging ? 'Release to upload' : 'Drag & drop configuration files here'}
                </p>
                <p className="text-xs text-ncasa-muted mt-1">or</p>
                <button
                  type="button"
                  onClick={(e) => { e.stopPropagation(); handleBrowse(); }}
                  className="mt-3 px-4 py-1.5 text-xs font-medium rounded border border-ncasa-border2 text-ncasa-subtle hover:bg-ncasa-surface2 hover:text-ncasa-text transition-colors focus:outline-none focus:ring-2 focus:ring-ncasa-accent"
                >
                  Browse Files
                </button>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".zip,.cfg,.conf,.txt"
                  className="hidden"
                  onChange={(e) => handleFile(e.target.files?.[0])}
                />
              </div>
            )}

            {/* ── SELECTED / UPLOADING file box ───────────────────────────── */}
            {(uploadState === STATE.SELECTED || isUploading) && selectedFile && (
              <div className="flex items-center gap-3 px-4 py-3 rounded border border-ncasa-accent/40 bg-ncasa-accent-l/10">
                <div className="p-2 rounded bg-ncasa-accent-l/20 border border-ncasa-accent/30">
                  <File size={16} className="text-ncasa-accent" />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-ncasa-text truncate">{selectedFile.name}</p>
                  <p className="text-xs text-ncasa-muted">
                    {formatBytes(selectedFile.size)}
                    {' · '}
                    <span className="uppercase font-mono">{selectedFile.name.split('.').pop()}</span>
                  </p>
                </div>
                {!isUploading && (
                  <button
                    onClick={handleRemoveFile}
                    className="text-ncasa-muted hover:text-sev-critical transition-colors p-1 rounded"
                    aria-label="Remove file"
                  >
                    <X size={16} />
                  </button>
                )}
              </div>
            )}

            {/* ── ERROR drop zone ─────────────────────────── */}
            {uploadState === STATE.ERROR && !selectedFile && (
              <div
                onDrop={handleDrop}
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onClick={handleBrowse}
                className="flex flex-col items-center justify-center border-2 border-dashed border-sev-critical/40 bg-sev-critical-bg rounded-lg py-12 px-6 text-center cursor-pointer"
              >
                <UploadCloud size={36} className="mb-3 text-sev-critical/60" />
                <p className="text-sm text-ncasa-subtle">Drop a different file or</p>
                <button
                  type="button"
                  onClick={(e) => { e.stopPropagation(); handleBrowse(); }}
                  className="mt-3 px-4 py-1.5 text-xs font-medium rounded border border-ncasa-border2 text-ncasa-subtle hover:bg-ncasa-surface2 transition-colors"
                >
                  Browse Files
                </button>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".zip,.cfg,.conf,.txt"
                  className="hidden"
                  onChange={(e) => handleFile(e.target.files?.[0])}
                />
              </div>
            )}
          </div>

          {/* Step 2: Framework */}
          <div className="bg-ncasa-surface border border-ncasa-border rounded p-5 space-y-4">
            <div className="flex items-center gap-2 mb-1">
              <span className="flex items-center justify-center w-5 h-5 rounded-full bg-ncasa-accent text-white text-[10px] font-bold shrink-0">2</span>
              <p className="text-sm font-semibold text-ncasa-text">Security Framework</p>
            </div>
            <p className="text-xs text-ncasa-muted">Select the compliance framework to audit against.</p>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {FRAMEWORKS.map((fw) => {
                const isSelected = selectedFramework === fw.id && fw.available;
                return (
                  <div
                    key={fw.id}
                    onClick={() => fw.available && !isUploading && setSelectedFramework(fw.id)}
                    className={`
                      relative rounded border p-4 transition-colors duration-150
                      ${!fw.available
                        ? 'opacity-50 cursor-not-allowed border-ncasa-border'
                        : isUploading
                        ? 'border-ncasa-border cursor-not-allowed opacity-70'
                        : isSelected
                        ? 'border-ncasa-accent bg-ncasa-accent-l/30 cursor-pointer'
                        : 'border-ncasa-border hover:border-ncasa-border2 cursor-pointer hover:bg-ncasa-surface2'
                      }
                    `}
                  >
                    {!fw.available && (
                      <span className="absolute top-2 right-2 text-[10px] font-semibold px-1.5 py-0.5 rounded bg-ncasa-surface2 text-ncasa-muted border border-ncasa-border">
                        Coming Soon
                      </span>
                    )}
                    {isSelected && (
                      <CheckCircle2 size={14} className="absolute top-2 right-2 text-ncasa-accent" />
                    )}
                    <p className="text-sm font-semibold text-ncasa-text mb-1">{fw.name}</p>
                    <p className="text-xs text-ncasa-muted leading-relaxed">{fw.description}</p>
                  </div>
                );
              })}
            </div>
          </div>

          {/* ── Error message ─────────────────────────────────────────────── */}
          {uploadState === STATE.ERROR && errorMessage && (
            <div className="flex items-start gap-3 px-4 py-3 rounded border border-sev-critical/30 bg-sev-critical-bg text-sm">
              <AlertCircle size={16} className="text-sev-critical shrink-0 mt-0.5" />
              <p className="text-sev-critical">{errorMessage}</p>
            </div>
          )}

          {/* ── Submit button ─────────────────────────────────────────────── */}
          <div className="flex items-center gap-3">
            <Button
              variant="primary"
              size="md"
              onClick={handleStartAudit}
              disabled={!selectedFile || isUploading}
              id="start-audit-btn"
              icon={isUploading ? Loader2 : Shield}
            >
              {isUploading ? 'Uploading & Ingesting…' : 'Start Audit'}
            </Button>

            {isUploading && (
              <p className="text-xs text-ncasa-muted animate-pulse">
                Processing file & creating configuration inventory…
              </p>
            )}
            {!selectedFile && uploadState !== STATE.ERROR && (
              <p className="text-xs text-ncasa-muted">Upload a configuration file to continue.</p>
            )}
          </div>
        </>
      )}
    </div>
  );
}
