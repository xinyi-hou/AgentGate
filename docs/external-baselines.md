# Deployable External Guard Baselines

This evaluation distinguishes guards that can be rerun in the local environment from results
copied from another paper. The local runner currently supports two public, self-hosted guards on
the 1,220 strict-mode steps in TS-Bench AgentDojo-Traj:

- `protectai-pi` uses
  [`protectai/deberta-v3-base-prompt-injection-v2`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2),
  the prompt-injection detector selected by
  [AgentDojo](https://github.com/ethz-spylab/agentdojo). It scans only the latest tool output. Inputs longer than the
  model's 512-token limit are scanned with overlapping 128-token windows, and the maximum
  injection probability is compared with the published default threshold of 0.5.
- `qwen3guard` uses
  [`Qwen/Qwen3Guard-Gen-0.6B`](https://huggingface.co/Qwen/Qwen3Guard-Gen-0.6B). It receives a generic serialization of the user
  task, environment, interaction history, and candidate action. `Unsafe` and `Controversial` are
  blocked under TS-Bench strict mode. The wrapper retains bounded task, environment, recent
  history, and action sections; it does not contain benchmark phrases or labels.

Both baselines run locally from their public model weights. Predictions with invalid output are
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

Run the two guards on exactly the same AgentDojo-Traj records:

```bash
agentgate evaluate-external-guard \
  --source benchmarks/external/toolsafe/TS-Bench/agentdojo-traj \
  --guard protectai-pi --batch-size 32 \
  --output artifacts/results/external-baselines/protectai-pi-agentdojo.json

agentgate evaluate-external-guard \
  --source benchmarks/external/toolsafe/TS-Bench/agentdojo-traj \
  --guard qwen3guard --batch-size 4 \
  --output artifacts/results/external-baselines/qwen3guard-agentdojo.json
```

`HF_ENDPOINT` may be set to an accessible Hugging Face mirror. CPU thread counts can be set with
`OMP_NUM_THREADS` and `MKL_NUM_THREADS`; these settings affect runtime but not predictions.

## Results

The following external rows are complete local reruns. The AgentGate row is the complete
DeepSeek-v4-Flash configuration currently reported in `docs/paper/5.Evaluation.tex`; it is shown
as the comparison target and was not rerun during this baseline deployment task.

| Method | TP | FP | TN | FN | ACC | F1 | FNR | FPR | Mean CPU inference/step |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Qwen3Guard-Gen-0.6B (local rerun) | 12 | 12 | 856 | 340 | 71.15% | 6.38% | 96.59% | 1.38% | 1,802.06 ms |
| ProtectAI PI detector (local rerun) | 185 | 127 | 741 | 167 | 75.90% | 55.72% | 47.44% | 14.63% | 337.75 ms |
| AgentGate + DeepSeek-v4-Flash (current result) | 345 | 63 | 805 | 7 | 94.26% | 90.79% | 1.99% | 7.26% | not compared |

At interaction level, the 1,220 steps form 589 interactions: 334 contain at least one unsafe
step and 255 are entirely benign. Qwen3Guard leaves 96.11% of attack interactions unblocked and
completes 98.82% of benign interactions. ProtectAI reduces interaction attack success to 33.53%,
while completing 81.18% of benign interactions. Neither external guard produced a parse failure.

Qwen3Guard's low false-positive rate is not evidence of effective protection: it predicts only
24 of 1,220 steps as unsafe and misses 340 of 352 unsafe steps. ProtectAI detects explicit
instructions in returned content more often, but it cannot determine whether an otherwise benign
action is necessary for the user's task. Relative to ProtectAI, the current AgentGate result is
18.36 percentage points higher in accuracy and 35.07 points higher in F1, while reducing FNR by
45.45 points and FPR by 7.37 points.

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
