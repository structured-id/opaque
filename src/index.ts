// @structured-id/opaque: OPAQUE on the Pallas curve with a Zero-Knowledge
// Password Policy (ZKPP) proof. Apache-2.0; see NOTICE for the patent on the
// ZKPP method and the grant that covers this package.
export { loadZkppClient, ZkppUnavailableError } from "./loader.js";
export type {
  LoadZkppOptions,
  PasswordHistoryContext,
  PasswordHistoryDomain,
  PasswordHistoryEvaluation,
  PasswordHistoryInputs,
  PasswordHistoryRequest,
  ProveOptions,
  ZkppClient,
  ZkppKernelFallback,
  ZkppLoginStart,
  ZkppProof,
  ZkppRegistrationStart,
} from "./loader.js";
export { selectKernel } from "./capabilities.js";
export type {
  Capabilities,
  Kernel,
  TsKernel,
  WasmKernel,
} from "./capabilities.js";
export { registerZkppKernel } from "./kernel.js";
export type { ZkppKernelFactory } from "./kernel.js";
export {
  DEFAULT_STEP_MS,
  PREPARE_STEPS,
  PROVE_STEPS,
  ProgressPlan,
  stepOf,
} from "./progress.js";
export type {
  PlanSegment,
  PrepareStep,
  ProgressPlanOptions,
  ProgressStep,
  ZkppProgress,
  ZkppStage,
} from "./progress.js";
