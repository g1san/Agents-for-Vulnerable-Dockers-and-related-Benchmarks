import math
import json
import builtins
import numpy as np
import pandas as pd
import seaborn as sns
from pathlib import Path
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
from matplotlib.lines import Line2D
from matplotlib.ticker import FuncFormatter
from IPython.display import display
from data_processing import get_val_set_data


def env_gen_wsm_model_performance_comparison():
    df = pd.concat([
        get_val_set_data(model="GPT-4o", logs_set="6th"),
        get_val_set_data(model="GPT-5", logs_set="3rd"),
        get_val_set_data(model="gpt-oss-120b", logs_set="2nd"),
    ])

    data_dict = {}
    # Web search modes
    modes = ['OpenAI Search', 'Custom Search', 'CVE-based Search']
    for model, model_df in df.groupby("model"):
        data_dict[model] = []
        for wsm in modes:
            if model == "gpt-oss-120b" and wsm == 'OpenAI Search':
                data_dict[model].append(0.0)
                continue
            print(f"--- {model} [{wsm}] ---")
            model_wsm_df = model_df[model_df["web_search_mode"] == wsm]
            eg_ok = model_wsm_df["docker_builds"] & model_wsm_df["docker_runs"] & model_wsm_df["code_hard_version"] & model_wsm_df["network_setup"]
            print(round(len(model_wsm_df[eg_ok]) * 100 / len(model_wsm_df), 2))
            data_dict[model].append(round(len(model_wsm_df[eg_ok]) * 100 / len(model_wsm_df), 2))
            print("\n")

    display(data_dict)

    # Set style similar to reference
    plt.style.use('seaborn-v0_8-paper')
    plt.rcParams.update({
        'font.family': 'serif',
        'axes.labelsize': 11,
        'xtick.labelsize': 11,
        'ytick.labelsize': 11,
        'legend.fontsize': 10,
        'figure.titlesize': 12
    })

    # Define color scheme similar to reference
    colors = {
        'OpenAI Search': '#ec807c',          # Medium-soft red
        'Custom Search': '#62a9dd',         # Medium-soft blue
        'CVE-based Search': '#8ac96b', # Medium-soft green
    }

    # Define patterns for bars
    patterns = {
        'OpenAI Search': '--',
        'Custom Search': '\\\\',
        'CVE-based Search': '//',
    }

    # Create figure
    fig, ax = plt.subplots(figsize=(6, 4))

    # Prepare data for plotting
    models = list(data_dict.keys())
    n_models = len(models)
    n_modes = len(modes)

    # Set width of bars and positions
    bar_width = 0.25
    x = np.arange(n_models)

    # Plot bars for each mode
    bars_list = []
    for i, mode in enumerate(modes):
        values = [data_dict[model][i] for model in models]
        offset = bar_width * (i - 1)
        bars = ax.bar(x + offset, values, bar_width, 
                    color=colors[mode], 
                    edgecolor='black',
                    hatch=patterns[mode])
        bars_list.append(bars)

    # Customize plot
    ax.set_xlabel('')
    ax.set_ylabel('Successful Environment Generation Runs (%)')
    ax.set_xticks(x)
    ax.set_xticklabels(models)
    ax.set_yticks(range(0, 101, 10))
    ax.set_yticklabels(range(0, 101, 10))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f'{y:.0f}%'))
    ax.set_ylim(0, 100)
    ax.grid(True, axis='y', linestyle='--', alpha=0.7)

    # Create custom legend with similar style to reference
    # legend_elements = [
    #     Patch(facecolor=colors['OpenAI Search'], hatch=patterns['OpenAI Search'], 
    #         label='OpenAI Search', edgecolor='black'),
    #     Patch(facecolor=colors['Custom Search'], hatch=patterns['Custom Search'], 
    #         label='Custom Search', edgecolor='black'),
    #     Patch(facecolor=colors['CVE-based Search'], hatch=patterns['CVE-based Search'], 
    #         label='CVE-based Search', edgecolor='black'),
    # ]
# 
    # # Add legend above the plot
    # ax.legend(handles=legend_elements,
    #         bbox_to_anchor=(0.5, 1.065),
    #         loc='center',
    #         ncols=3,
    #         columnspacing=0.5,
    #         handletextpad=0.2,
    #         handleheight=1.0,
    #         handlelength=1.5,
    #         frameon=False,
    #         title='Web Search Mode',)
    
    autonomous_elements = [
        Patch(facecolor=colors['OpenAI Search'], hatch=patterns['OpenAI Search'], 
            label='OpenAI', edgecolor='black'),
        Patch(facecolor=colors['Custom Search'], hatch=patterns['Custom Search'], 
            label='Custom', edgecolor='black'),
    ]

    fixed_elements = [
        Patch(facecolor=colors['CVE-based Search'], hatch=patterns['CVE-based Search'], 
            label='CVE-based', edgecolor='black'),
    ]
    
    # Legends inside figure
    fig.legend(handles=autonomous_elements, title="Autonomous Strategies",
                loc="upper left", bbox_to_anchor=(0.15, 1.025),
                frameon=False, ncol=2)
    fig.legend(handles=fixed_elements, title="Fixed Strategies",
                loc="upper right", bbox_to_anchor=(0.85, 1.025),
                frameon=False)

    plt.show()
    

    # Add value labels on bars
    # for i, mode in enumerate(modes):
    #     values = [data_dict[model][i] for model in models]
    #     offset = bar_width * (i - 1)
    #     for j, v in enumerate(values):
    #         if v > 0:
    #             ax.text(j + offset, v + 1, f'{v:.0f}%', 
    #                 ha='center', va='bottom')
    plt.show()
env_gen_wsm_model_performance_comparison()

    
def env_gen_wsm_multirun_performance_comparison():
    df = pd.concat([
        get_val_set_data(model="GPT-4o", logs_set="5th"),
        get_val_set_data(model="GPT-4o", logs_set="6th"),
        get_val_set_data(model="GPT-4o", logs_set="7th"),
    ])

    data_dict = {}
    for logs_set, logs_set_df in df.groupby("logs_set"):
        data_dict[logs_set] = []
        for wsm, logs_set_wsm_df in logs_set_df.groupby("web_search_mode"):
            print(f"--- {logs_set} [{wsm}] ---")
            condition = logs_set_wsm_df["docker_builds"] & logs_set_wsm_df["docker_runs"] & logs_set_wsm_df["code_hard_version"] & logs_set_wsm_df["network_setup"]
            print(round(len(logs_set_wsm_df[condition]) * 100 / len(logs_set_wsm_df), 2))
            data_dict[logs_set].append(round(len(logs_set_wsm_df[condition]) * 100 / len(logs_set_wsm_df), 2))
            print("\n")

    display(data_dict)

    # Web search modes for legend
    modes = ['Custom Search', 'CVE-based Search', 'OpenAI Search']

    # Set style similar to reference
    plt.style.use('seaborn-v0_8-paper')
    plt.rcParams.update({
        'font.family': 'serif',
        'axes.labelsize': 16,
        'xtick.labelsize': 16,
        'ytick.labelsize': 16,
        'legend.fontsize': 16
    })

    # Define color scheme similar to reference
    colors = {
        'Custom Search': '#62a9dd',         # Medium-soft blue
        'CVE-based Search': '#8ac96b', # Medium-soft green
        'OpenAI Search': '#ec807c'          # Medium-soft red
    }

    # Define patterns for bars
    patterns = {
        'Custom Search': '\\\\',
        'CVE-based Search': '//',
        'OpenAI Search': '--'
    }

    # Create figure
    fig, ax = plt.subplots(figsize=(10, 8))

    # Prepare data for plotting
    logs_sets = list(data_dict.keys())
    n_logs_set = len(logs_sets)
    n_modes = len(modes)

    # Set width of bars and positions
    bar_width = 0.25
    x = np.arange(n_logs_set)

    # Plot bars for each mode
    bars_list = []
    for i, mode in enumerate(modes):
        values = [data_dict[logs_set][i] for logs_set in logs_sets]
        offset = bar_width * (i - 1)
        bars = ax.bar(x + offset, values, bar_width, 
                    color=colors[mode], 
                    edgecolor='black',
                    hatch=patterns[mode])
        bars_list.append(bars)

    # Customize plot
    ax.set_xlabel('', fontsize=16)
    ax.set_ylabel('Successful Environment Generation Runs (%)', fontsize=16)
    ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f'{y:.0f}%'))
    ax.set_xticks(x)
    ax.set_xticklabels(["1st Test", "2nd Test", "3rd Test"])
    ax.set_ylim(0, 100)
    ax.grid(True, axis='y', linestyle='--', alpha=0.7)

    # Create custom legend with similar style to reference
    legend_elements = [
        Patch(facecolor=colors['Custom Search'], hatch=patterns['Custom Search'], 
            label='Custom Search', edgecolor='black'),
        Patch(facecolor=colors['CVE-based Search'], hatch=patterns['CVE-based Search'], 
            label='CVE-based Search', edgecolor='black'),
        Patch(facecolor=colors['OpenAI Search'], hatch=patterns['OpenAI Search'], 
            label='OpenAI Search', edgecolor='black')
    ]

    # Add legend above the plot
    ax.legend(handles=legend_elements,
            bbox_to_anchor=(0.5, 1.05),
            loc='center',
            ncols=3,
            columnspacing=0.5,
            handletextpad=0.2,
            handleheight=1.0,
            handlelength=1.5,
            frameon=False,
            title='Web Search Mode',
            title_fontsize=16)

    # Add value labels on bars
    for i, mode in enumerate(modes):
        values = [data_dict[logs_set][i] for logs_set in logs_sets]
        offset = bar_width * (i - 1)
        for j, v in enumerate(values):
            if v > 0:
                ax.text(j + offset, v + 1, f'{v:.0f}%', 
                    ha='center', va='bottom', fontsize=16)

    plt.tight_layout()
    plt.show()
# env_gen_wsm_multirun_performance_comparison()


def env_gen_wsm_model_performance_comparison_onlyEG():
    df = pd.concat([
        get_val_set_data(model="GPT-4o", logs_set="5th"),
        get_val_set_data(model="GPT-5", logs_set="3rd"),
        get_val_set_data(model="gpt-oss-120b", logs_set="2nd"),
    ])

    data_dict = {}
    # Web search modes
    modes = ['OpenAI Search', 'Custom Search', 'CVE-based Search']
    for model, model_df in df.groupby("model"):
        data_dict[model] = []
        for wsm in modes:
            if model == "gpt-oss-120b" and wsm == 'OpenAI Search':
                data_dict[model].append(0.0)
                continue
            print(f"--- {model} [{wsm}] ---")
            model_wsm_df = model_df[model_df["web_search_mode"] == wsm]
            eg_started = model_wsm_df['hard_service'] & model_wsm_df['hard_version'] & model_wsm_df['soft_services']
            eg_ok = model_wsm_df["docker_builds"] & model_wsm_df["docker_runs"] & model_wsm_df["code_hard_version"] & model_wsm_df["network_setup"]
            print(round(len(model_wsm_df[eg_ok]) * 100 / len(model_wsm_df[eg_started]), 2))
            data_dict[model].append(round(len(model_wsm_df[eg_ok]) * 100 / len(model_wsm_df[eg_started]), 2))
            print("\n")

    display(data_dict)

    # Set style similar to reference
    plt.style.use('seaborn-v0_8-paper')
    plt.rcParams.update({
        'font.family': 'serif',
        'axes.labelsize': 11,
        'xtick.labelsize': 11,
        'ytick.labelsize': 11,
        'legend.fontsize': 10,
        'figure.titlesize': 12
    })

    # Define color scheme similar to reference
    colors = {
        'OpenAI Search': '#ec807c',          # Medium-soft red
        'Custom Search': '#62a9dd',         # Medium-soft blue
        'CVE-based Search': '#8ac96b', # Medium-soft green
    }

    # Define patterns for bars
    patterns = {
        'OpenAI Search': '--',
        'Custom Search': '\\\\',
        'CVE-based Search': '//',
    }

    # Create figure
    fig, ax = plt.subplots(figsize=(6, 4))

    # Prepare data for plotting
    models = list(data_dict.keys())
    n_models = len(models)
    n_modes = len(modes)

    # Set width of bars and positions
    bar_width = 0.25
    x = np.arange(n_models)

    # Plot bars for each mode
    bars_list = []
    for i, mode in enumerate(modes):
        values = [data_dict[model][i] for model in models]
        offset = bar_width * (i - 1)
        bars = ax.bar(x + offset, values, bar_width, 
                    color=colors[mode], 
                    edgecolor='black',
                    hatch=patterns[mode])
        bars_list.append(bars)

    # Customize plot
    ax.set_xlabel('')
    ax.set_ylabel('Successful Environment Generation Runs (%)')
    ax.set_xticks(x)
    ax.set_xticklabels(models)
    ax.set_yticks(range(0, 101, 10))
    ax.set_yticklabels(range(0, 101, 10))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f'{y:.0f}%'))
    ax.set_ylim(0, 100)
    ax.grid(True, axis='y', linestyle='--', alpha=0.7)

    # Create custom legend with similar style to reference
    # legend_elements = [
    #     Patch(facecolor=colors['OpenAI Search'], hatch=patterns['OpenAI Search'], 
    #         label='OpenAI Search', edgecolor='black'),
    #     Patch(facecolor=colors['Custom Search'], hatch=patterns['Custom Search'], 
    #         label='Custom Search', edgecolor='black'),
    #     Patch(facecolor=colors['CVE-based Search'], hatch=patterns['CVE-based Search'], 
    #         label='CVE-based Search', edgecolor='black'),
    # ]
# 
    # # Add legend above the plot
    # ax.legend(handles=legend_elements,
    #         bbox_to_anchor=(0.5, 1.065),
    #         loc='center',
    #         ncols=3,
    #         columnspacing=0.5,
    #         handletextpad=0.2,
    #         handleheight=1.0,
    #         handlelength=1.5,
    #         frameon=False,
    #         title='Web Search Mode',)
    
    autonomous_elements = [
        Patch(facecolor=colors['OpenAI Search'], hatch=patterns['OpenAI Search'], 
            label='OpenAI', edgecolor='black'),
        Patch(facecolor=colors['Custom Search'], hatch=patterns['Custom Search'], 
            label='Custom', edgecolor='black'),
    ]

    fixed_elements = [
        Patch(facecolor=colors['CVE-based Search'], hatch=patterns['CVE-based Search'], 
            label='CVE-based', edgecolor='black'),
    ]
    
    # Legends inside figure
    fig.legend(handles=autonomous_elements, title="Autonomous Strategies",
                loc="upper left", bbox_to_anchor=(0.15, 1.025),
                frameon=False, ncol=2)
    fig.legend(handles=fixed_elements, title="Fixed Strategies",
                loc="upper right", bbox_to_anchor=(0.85, 1.025),
                frameon=False)

    plt.show()
    

    # Add value labels on bars
    # for i, mode in enumerate(modes):
    #     values = [data_dict[model][i] for model in models]
    #     offset = bar_width * (i - 1)
    #     for j, v in enumerate(values):
    #         if v > 0:
    #             ax.text(j + offset, v + 1, f'{v:.0f}%', 
    #                 ha='center', va='bottom')
    plt.show()
# env_gen_wsm_model_performance_comparison_onlyEG()
    
    
def env_gen_wsm_multirun_performance_comparison_onlyEG():
    df = pd.concat([
        get_val_set_data(model="GPT-4o", logs_set="5th"),
        get_val_set_data(model="GPT-4o", logs_set="6th"),
        get_val_set_data(model="GPT-4o", logs_set="7th"),
    ])

    data_dict = {}
    # Web search modes for legend
    modes = ['OpenAI Search', 'Custom Search', 'CVE-based Search']
    for logs_set, logs_set_df in df.groupby("logs_set"):
        data_dict[logs_set] = []
        for wsm in modes:
            print(f"--- {logs_set} [{wsm}] ---")
            logs_set_wsm_df = logs_set_df[logs_set_df["web_search_mode"] == wsm]
            eg_started = logs_set_wsm_df['hard_service'] & logs_set_wsm_df['hard_version'] & logs_set_wsm_df['soft_services']
            eg_ok = logs_set_wsm_df["docker_builds"] & logs_set_wsm_df["docker_runs"] & logs_set_wsm_df["code_hard_version"] & logs_set_wsm_df["network_setup"]
            print(round(len(logs_set_wsm_df[eg_ok]) * 100 / len(logs_set_wsm_df[eg_started]), 2))
            data_dict[logs_set].append(round(len(logs_set_wsm_df[eg_ok]) * 100 / len(logs_set_wsm_df[eg_started]), 2))
            print("\n")

    display(data_dict)

    # Set style similar to reference
    plt.style.use('seaborn-v0_8-paper')
    plt.rcParams.update({
        'font.family': 'serif',
        'axes.labelsize': 11,
        'xtick.labelsize': 11,
        'ytick.labelsize': 11,
        'legend.fontsize': 10,
        'figure.titlesize': 12
    })

    # Define color scheme similar to reference
    colors = {
        'OpenAI Search': '#ec807c',          # Medium-soft red
        'Custom Search': '#62a9dd',         # Medium-soft blue
        'CVE-based Search': '#8ac96b', # Medium-soft green
    }

    # Hatches now map to TESTS (logs_sets), not modes
    logs_sets = list(data_dict.keys())          # e.g. ['5th', '6th', '7th']
    test_labels = {
        '5th': '1st Test',
        '6th': '2nd Test',
        '7th': '3rd Test'
    }
    test_patterns = {
        '5th': '\\\\',    # 1st test
        '6th': '--',   # 2nd test
        '7th': '//',    # 3rd test
    }

    # Create figure
    fig, ax = plt.subplots(figsize=(6, 4))

    # Prepare data for plotting
    n_logs_set = len(logs_sets)     # 3 tests
    n_modes = len(modes)            # 3 modes
    bar_width = 0.25

    # positions of each mode-group
    x = np.arange(n_modes) * 1.2              # spacing between groups

    # Plot bars grouped by MODE (color), hatched by TEST
    for t_index, logs_set in enumerate(logs_sets):      # loop over tests
        for m_index, mode in enumerate(modes):          # loop over modes
            value = data_dict[logs_set][m_index]
            offset = (t_index - 1) * bar_width          # center 3 bars around group center

            ax.bar(
                x[m_index] + offset,
                value,
                bar_width,
                color=colors[mode],                     # color = mode
                edgecolor="black",
                hatch=test_patterns[logs_set]           # hatch = test
            )

    # Axis & ticks
    ax.set_ylabel("Successful Environment Generation Runs (%)")
    ax.set_yticks(range(0, 101, 10))
    ax.set_yticklabels(range(0, 101, 10))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f'{y:.0f}%'))
    ax.set_xticks(x)
    ax.set_xticklabels(modes)
    ax.set_ylim(0, 100)
    ax.grid(True, axis='y', linestyle='--', alpha=0.7)

    # Add labels above bars
    # for t_index, logs_set in enumerate(logs_sets):
    #     for m_index, mode in enumerate(modes):
    #         value = data_dict[logs_set][m_index]
    #         offset = (t_index - 1) * bar_width
    #         ax.text(
    #             x[m_index] + offset,
    #             value + 1,
    #             f"{value:.0f}%",
    #             ha='center',
    #             va='bottom',
    #         )

   # --- Legends ---

    # Legend 1: colors = Web Search aMode (left side)
    legend_elements = [
        Patch(facecolor='white', edgecolor='black',
            hatch=test_patterns[ls], label=test_labels[ls])
        for ls in logs_sets
    ]

    ax.legend(
        handles=legend_elements,
        bbox_to_anchor=(0.5, 1.05),   # centered top
        loc='center',
        ncols=3,
        frameon=False,
        columnspacing=0.8,
        handletextpad=0.2,
        handleheight=1.0,
        handlelength=1.5,
    )
    plt.show()
# env_gen_wsm_multirun_performance_comparison_onlyEG()


def env_gen_wsm_multirun_performance_consistency():
    df = pd.concat([
        get_val_set_data(model="GPT-4o", logs_set="5th"),
        get_val_set_data(model="GPT-4o", logs_set="6th"),
        get_val_set_data(model="GPT-4o", logs_set="7th"),
    ])

    data_dict = {}
    modes = ['OpenAI Search', 'Custom Search', 'CVE-based Search']
    for wsm in modes:
        wsm_df = df[df["web_search_mode"] == wsm]
        data_dict[wsm] = []
        for cve, cve_wsm_df in wsm_df.groupby("cve_id"):
            condition = cve_wsm_df["docker_builds"] & cve_wsm_df["docker_runs"] & cve_wsm_df["code_hard_version"] & cve_wsm_df["network_setup"]
            print(cve, wsm, len(cve_wsm_df[condition]))
            data_dict[wsm].append(len(cve_wsm_df[condition]))
        data_dict[wsm] = [data_dict[wsm].count(0), data_dict[wsm].count(1), data_dict[wsm].count(2), data_dict[wsm].count(3)]

    display(data_dict)

    # ---------- STYLE ----------
    plt.style.use('seaborn-v0_8-paper')
    plt.rcParams.update({
        'font.family': 'serif',
        'axes.labelsize': 11,
        'xtick.labelsize': 11,
        'ytick.labelsize': 11,
        'legend.fontsize': 10,
        'figure.titlesize': 12
    })

    # ---------- COLOR + LINE STYLES ----------
    colors = {
        'OpenAI Search': '#ec807c',
        'Custom Search': '#62a9dd',
        'CVE-based Search': '#8ac96b',
    }

    patterns = {
        'OpenAI Search': '-.',
        'Custom Search': '--',
        'CVE-based Search': '-',
    }

    # ---------- X VALUES ----------
    x_values = [0, 1, 2, 3]

    # =========================================================
    # FIGURE 1 — CDF
    # =========================================================
    fig, ax = plt.subplots(figsize=(6, 4))

    for method, counts in data_dict.items():
        cdf = np.cumsum(counts)
        ax.plot(
            x_values, cdf/cdf.max(),
            color=colors[method],
            linestyle=patterns[method],
            linewidth=2.5,
            marker='o',
            markersize=8,
        )

    # Axis formatting (CDF)
    ax.set_xlabel('Successful Runs per CVE')
    ax.set_ylabel('Cumulative Distribution Function')
    ax.set_xticks(x_values)
    ax.set_xticklabels(['0/3', '1/3', '2/3', '3/3'])
    ax.set_yticks(np.arange(0, 1.1, 0.1))
    ax.set_yticklabels([round(el, 1) for el in np.arange(0, 1.1, 0.1)])
    ax.set_ylim(-0.05, 1.05)
    ax.grid(True, linestyle='--', alpha=0.7)

    # ---------- LEGEND LINE ELEMENTS ----------
    autonomous_elements = [
        Line2D([0], [0], color=colors['OpenAI Search'],
            linestyle=patterns['OpenAI Search'], linewidth=2.5,
            marker='o', markersize=8, label='OpenAI'),
        Line2D([0], [0], color=colors['Custom Search'],
            linestyle=patterns['Custom Search'], linewidth=2.5,
            marker='o', markersize=8, label='Custom'),
    ]

    fixed_elements = [
        Line2D([0], [0], color=colors['CVE-based Search'],
            linestyle=patterns['CVE-based Search'], linewidth=2.5,
            marker='o', markersize=8, label='CVE-based'),
    ]
    
    # Legends inside figure
    fig.legend(handles=autonomous_elements, title="Autonomous Strategies",
                loc="upper left", bbox_to_anchor=(0.15, 1.025),
                frameon=False, ncol=2)
    fig.legend(handles=fixed_elements, title="Fixed Strategies",
                loc="upper right", bbox_to_anchor=(0.85, 1.025),
                frameon=False)

    plt.show()
# env_gen_wsm_multirun_performance_consistency()
