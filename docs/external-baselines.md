# Deployable External Guard Baselines

This evaluation distinguishes guards that can be rerun in the local environment from results
copied from another paper. The local runner supports two public, self-hosted guards on their
applicable TS-Bench strict-mode tracks:

- `protectai-pi` uses
  [`protectai/deberta-v3-base-prompt-injection-v2`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2),
  the prompt-injection detector selected by
  [AgentDojo](https://github.com/ethz-spylab/agentdojo). It scans only the latest tool output. Inputs longer than the
  model's 512-token limit are scanned with overlapping 128-token windows, and the maximum
  injection probability is compared with the published default threshold of 0.5. This input
  contract applies to ASB-Traj and AgentDojo-Traj, but not to AgentHarm-Traj's task-level harm
  classification.
- `qwen3guard` uses
  [`Qwen/Qwen3Guard-Gen-0.6B`](https://huggingface.co/Qwen/Qwen3Guard-Gen-0.6B). It receives a generic serialization of the user
  task, environment, interaction history, and candidate action. `Unsafe` and `Controversial` are
  blocked under TS-Bench strict mode. The wrapper retains bounded task, environment, recent
  history, and action sections; it does not contain benchmark phrases or labels.

Both baselines run locally from their public model weights. Qwen3Guard is evaluated on all three
tracks; ProtectAI is evaluated on ASB-Traj and AgentDojo-Traj. Predictions with invalid output are
retained and denied rather than silently removed. Reports use AgentGate's common TP/FP/TN/FN
implementation and include both step-level metrics and interaction-level attack success and
benign completion rates.

## Reproduction

Install a CPU PyTorch wheel first when the host does not have CUDA, then install the baseline
extra:

```bash
python -m pip install --index-url https://download.pytorch.org/whl/cpu 'torch>=2.6,<3'
python -m pip install -e '.[baselines]'
```

Run the guards on their applicable records:

```bash
agentgate evaluate-external-guard \
  --source benchmarks/external/toolsafe/TS-Bench/agentdojo-traj \
  --guard protectai-pi --batch-size 32 \
  --output artifacts/results/external-baselines/protectai-pi-agentdojo.json

agentgate evaluate-external-guard \
  --source benchmarks/external/toolsafe/TS-Bench/agentdojo-traj \
  --guard qwen3guard --batch-size 4 \
  --output artifacts/results/external-baselines/qwen3guard-agentdojo.json

agentgate evaluate-external-guard \
  --source benchmarks/external/toolsafe/TS-Bench/agentharm-traj \
  --guard qwen3guard --batch-size 4 \
  --output artifacts/results/external-baselines/qwen3guard-agentharm.json

agentgate evaluate-external-guard \
  --source benchmarks/external/toolsafe/TS-Bench/asb-traj \
  --guard qwen3guard --batch-size 8 \
  --output artifacts/results/external-baselines/qwen3guard-asb.json

agentgate evaluate-external-guard \
  --source benchmarks/external/toolsafe/TS-Bench/asb-traj \
  --guard protectai-pi --batch-size 32 \
  --output artifacts/results/external-baselines/protectai-pi-asb.json
```

`HF_ENDPOINT` may be set to an accessible Hugging Face mirror. CPU thread counts can be set with
`OMP_NUM_THREADS` and `MKL_NUM_THREADS`; these settings affect runtime but not predictions.

## Results

The following external rows are complete local reruns. The AgentGate row is the complete
DeepSeek-v4-Flash configuration currently reported in `docs/paper/5.Evaluation.tex`; it is shown
as the comparison target and was not rerun during this baseline deployment task.

| Method | Track | TP | FP | TN | FN | ACC | F1 | Recall | FPR | Mean CPU inference/step |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Qwen3Guard-Gen-0.6B | AgentHarm-Traj | 383 | 70 | 136 | 142 | 71.00% | 78.32% | 72.95% | 33.98% | 987.87 ms |
| Qwen3Guard-Gen-0.6B | ASB-Traj | 281 | 105 | 2,591 | 2,254 | 54.90% | 19.24% | 11.08% | 3.89% | 363.23 ms |
| Qwen3Guard-Gen-0.6B | AgentDojo-Traj | 12 | 12 | 856 | 340 | 71.15% | 6.38% | 3.41% | 1.38% | 1,802.06 ms |
| ProtectAI PI detector | ASB-Traj | 55 | 34 | 2,662 | 2,480 | 51.94% | 4.19% | 2.17% | 1.26% | 16.33 ms |
| ProtectAI PI detector | AgentDojo-Traj | 185 | 127 | 741 | 167 | 75.90% | 55.72% | 52.56% | 14.63% | 337.75 ms |
| AgentGate + DeepSeek-v4-Flash | AgentHarm-Traj | 486 | 48 | 158 | 39 | 88.10% | 91.78% | 92.57% | 23.30% | not compared |
| AgentGate + DeepSeek-v4-Flash | ASB-Traj | 2,290 | 390 | 2,306 | 245 | 87.86% | 87.82% | 90.34% | 14.47% | not compared |
| AgentGate + DeepSeek-v4-Flash | AgentDojo-Traj | 345 | 63 | 805 | 7 | 94.26% | 90.79% | 98.01% | 7.26% | not compared |

At interaction level, Qwen3Guard leaves 18.06%, 88.04%, and 96.11% of the AgentHarm, ASB, and
AgentDojo attack interactions unblocked, respectively. Its corresponding benign completion rates
are 67.20%, 100.00%, and 98.82%. ProtectAI leaves 96.70% of ASB and 33.53% of AgentDojo attack
interactions unblocked, while completing 96.11% and 81.18% of their benign interactions. None of
the five full local runs produced a parse failure.

Qwen3Guard detects task-level harm more often on AgentHarm, but its recall falls to 11.08% on ASB
and 3.41% on AgentDojo. ProtectAI detects explicit instructions in returned content more often on
AgentDojo, but reaches only 2.17% recall on ASB and cannot determine whether an otherwise benign
action is necessary for the user's task. These results expose the limits of transferring content
classifiers directly to task authorization and trajectory-risk decisions.

The inference measurements are batch-amortized CPU costs on the local evaluation host, excluding
model loading. They are not GPU latency estimates. The exact downloaded model revisions were
`90c9989b1a342275dd0d1a95aad283c04e075671` for ProtectAI and
`fada3b2f655b89601929198343c94cd2f64d93cc` for Qwen3Guard.

## Scope

These guards are deliberately not treated as equivalent systems. ProtectAI is a tool-output
injection detector, while Qwen3Guard is a general content-safety model over a complete candidate
step. Neither maintains task authorization contracts, data-flow labels, cumulative budgets, or
approval state.

[`Invariant Guardrails`](https://github.com/invariantlabs-ai/invariant) is straightforward to
deploy as a trace-policy engine, but its default local
`prompt_injection` detector uses the same ProtectAI model. Listing both as independent detection
baselines would duplicate one underlying classifier.
[`CaMeL`](https://github.com/google-research/camel-prompt-injection) is retained as a candidate
end-to-end system baseline: its public artifact must regenerate native AgentDojo trajectories with a
supported agent model, so its results cannot be mixed with fixed-step replay without a separate
experiment.
