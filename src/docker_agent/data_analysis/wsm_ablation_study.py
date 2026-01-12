import math
import json
import builtins
import numpy as np
import pandas as pd
import seaborn as sns
from pathlib import Path
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
from matplotlib.ticker import FuncFormatter
from IPython.display import display
from data_processing import get_val_set_data


def env_gen_multirun_ablation_study():
    df = pd.concat([
        get_val_set_data(model="GPT-4o", logs_set="5th"),
        get_val_set_data(model="GPT-4o", logs_set="6th"),
        get_val_set_data(model="GPT-4o", logs_set="7th"),
    ])

    data_dict = {}
    # Web search modes for legend
    modes = ['OpenAI Search', 'Custom Search', 'CVE-based Search']
    for logs_set, logs_set_df in df.groupby("logs_set"):
        data_dict[logs_set], temp_list = [], []
        for wsm in modes:
            print(f"--- {logs_set} [{wsm}] ---")
            logs_set_wsm_df = logs_set_df[logs_set_df["web_search_mode"] == wsm]
            condition = logs_set_wsm_df["docker_builds"] & logs_set_wsm_df["docker_runs"] & logs_set_wsm_df["code_hard_version"] & logs_set_wsm_df["network_setup"]
            print(round(len(logs_set_wsm_df[condition]) * 100 / len(logs_set_wsm_df), 2))
            temp_list.append(round(len(logs_set_wsm_df[condition]) * 100 / len(logs_set_wsm_df), 2))
            print("\n")
        data_dict[logs_set].append(temp_list)
    
    df_ablation = pd.concat([
        get_val_set_data(model="GPT-4o", logs_set="5th", add_ablation_results=True),
        get_val_set_data(model="GPT-4o", logs_set="6th", add_ablation_results=True),
        get_val_set_data(model="GPT-4o", logs_set="7th", add_ablation_results=True),
    ])

    for logs_set, logs_set_df in df_ablation.groupby("logs_set"):
        temp_list = []
        for wsm in modes:
            print(f"--- {logs_set} [{wsm}] ---")
            logs_set_wsm_df = logs_set_df[logs_set_df["web_search_mode"] == wsm]
            condition = logs_set_wsm_df["docker_builds"] & logs_set_wsm_df["docker_runs"] & logs_set_wsm_df["code_hard_version"] & logs_set_wsm_df["network_setup"]
            print(round(len(logs_set_wsm_df[condition]) * 100 / len(logs_set_wsm_df), 2))
            temp_list.append(round(len(logs_set_wsm_df[condition]) * 100 / len(logs_set_wsm_df), 2))
            print("\n")
        data_dict[logs_set].append(temp_list)

    for mode, lists in data_dict.items():
        data_dict[mode][1] = [a_i - b_i for a_i, b_i in zip(lists[1], lists[0])]
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

    # Colors — lighter for enabled (bottom), stronger for disabled (top)
    colors_enabled = {
        'OpenAI Search':  '#f5b8b6',   # lighter red
        'Custom Search':  '#a3d5f5',   # lighter blue
        'CVE-based Search': '#b8e49b', # lighter green
    }

    colors_disabled = {
        'OpenAI Search':  '#ec807c',   # stronger red
        'Custom Search':  '#62a9dd',   # stronger blue
        'CVE-based Search': '#8ac96b', # stronger green
    }

    # Hatch patterns encode TEST
    patterns_enabled = {
        '5th': '\\\\',
        '6th': '--',
        '7th': '//',
    }

    patterns_disabled = {
        '5th': '..',
        '6th': 'xx',
        '7th': 'oo',
    }

    fig, ax = plt.subplots(figsize=(6, 4))

    tests = list(data_dict.keys())          # ['5th', '6th', '7th']
    n_tests = len(tests)
    modes = ['OpenAI Search', 'Custom Search', 'CVE-based Search']
    n_modes = len(modes)

    bar_width = 0.25
    x = np.arange(n_modes)

    for t_index, logs_set in enumerate(tests):
        offset = bar_width * (t_index - (n_tests - 1) / 2)  # centers 3 tests

        for m_index, mode in enumerate(modes):
            enabled_val = data_dict[logs_set][0][m_index]     # bottom bars
            disabled_val = data_dict[logs_set][1][m_index]    # top bars
            xpos = x[m_index] + offset

            # Bottom: early stop enabled — lighter color + enabled hatching
            ax.bar(
                xpos,
                enabled_val,
                bar_width,
                color=colors_enabled[mode],
                edgecolor="black",
                linewidth=1.5,
                hatch=patterns_enabled[logs_set],
            )

            # Top: early stop disabled — stronger color + disabled hatching
            ax.bar(
                xpos,
                disabled_val,
                bar_width,
                bottom=enabled_val,
                color=colors_disabled[mode],
                edgecolor="black",
                linewidth=1.5,
                hatch=patterns_disabled[logs_set],
            )

    # Axes & formatting
    ax.set_ylabel("Successful Environment Generation Runs (%)")
    ax.set_yticks(range(0, 101, 10))
    ax.set_yticklabels(range(0, 101, 10))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f"{y:.0f}%"))
    ax.set_xticks(x)
    ax.set_xticklabels(modes)
    ax.set_ylim(0, 100)
    ax.grid(True, axis="y", linestyle="--", alpha=0.7)

    # Legend — explains hatch patterns only
    legend_elements = []
    for t, r in zip(tests, ['1st', '2nd', '3rd']):
        legend_elements.append(
            Patch(facecolor="white", edgecolor="black",
                hatch=patterns_enabled[t],
                label=f"{r} Test (Early Stop Enabled)")
        )
    for t, r in zip(tests, ['1st', '2nd', '3rd']):
        legend_elements.append(
            Patch(facecolor="white", edgecolor="black",
                hatch=patterns_disabled[t],
                label=f"{r} Test (Early Stop Disabled)")
        )

    ax.legend(
        handles=legend_elements,
        bbox_to_anchor=(0.5, 1.125),
        loc='center',
        ncols=2,
        frameon=False,
        columnspacing=0.8,
        handletextpad=0.4,
        handleheight=1.0,
        handlelength=1.5,
    )
    plt.show()
env_gen_multirun_ablation_study()


def vul_ass_multirun_ablation_study():
    df = pd.concat([
        get_val_set_data(model="GPT-4o", logs_set="5th"),
        get_val_set_data(model="GPT-4o", logs_set="6th"),
        get_val_set_data(model="GPT-4o", logs_set="7th"),
    ])

    data_dict = {}
    # Web search modes for legend
    modes = ['OpenAI Search', 'Custom Search', 'CVE-based Search']
    for logs_set, logs_set_df in df.groupby("logs_set"):
        data_dict[logs_set], temp_list = [], []
        for wsm in modes:
            print(f"--- {logs_set} [{wsm}] ---")
            logs_set_wsm_df = logs_set_df[logs_set_df["web_search_mode"] == wsm]
            condition = logs_set_wsm_df["docker_builds"] & logs_set_wsm_df["docker_runs"] & logs_set_wsm_df["code_hard_version"] & logs_set_wsm_df["network_setup"] & logs_set_wsm_df["docker_scout_vulnerable"]
            print(round(len(logs_set_wsm_df[condition]) * 100 / len(logs_set_wsm_df), 2))
            temp_list.append(round(len(logs_set_wsm_df[condition]) * 100 / len(logs_set_wsm_df), 2))
            print("\n")
        data_dict[logs_set].append(temp_list)
    
    df_ablation = pd.concat([
        get_val_set_data(model="GPT-4o", logs_set="5th", add_ablation_results=True),
        get_val_set_data(model="GPT-4o", logs_set="6th", add_ablation_results=True),
        get_val_set_data(model="GPT-4o", logs_set="7th", add_ablation_results=True),
    ])

    for logs_set, logs_set_df in df_ablation.groupby("logs_set"):
        temp_list = []
        for wsm in modes:
            print(f"--- {logs_set} [{wsm}] ---")
            logs_set_wsm_df = logs_set_df[logs_set_df["web_search_mode"] == wsm]
            condition = logs_set_wsm_df["docker_builds"] & logs_set_wsm_df["docker_runs"] & logs_set_wsm_df["code_hard_version"] & logs_set_wsm_df["network_setup"] & logs_set_wsm_df["docker_scout_vulnerable"]
            print(round(len(logs_set_wsm_df[condition]) * 100 / len(logs_set_wsm_df), 2))
            temp_list.append(round(len(logs_set_wsm_df[condition]) * 100 / len(logs_set_wsm_df), 2))
            print("\n")
        data_dict[logs_set].append(temp_list)

    for mode, lists in data_dict.items():
        data_dict[mode][1] = [a_i - b_i for a_i, b_i in zip(lists[1], lists[0])]
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

    # Colors — lighter for enabled (bottom), stronger for disabled (top)
    colors_enabled = {
        'OpenAI Search':  '#f5b8b6',   # lighter red
        'Custom Search':  '#a3d5f5',   # lighter blue
        'CVE-based Search': '#b8e49b', # lighter green
    }

    colors_disabled = {
        'OpenAI Search':  '#ec807c',   # stronger red
        'Custom Search':  '#62a9dd',   # stronger blue
        'CVE-based Search': '#8ac96b', # stronger green
    }

    # Hatch patterns encode TEST
    patterns_enabled = {
        '5th': '\\\\',
        '6th': '--',
        '7th': '//',
    }

    patterns_disabled = {
        '5th': '..',
        '6th': 'xx',
        '7th': 'oo',
    }

    fig, ax = plt.subplots(figsize=(6, 4))

    tests = list(data_dict.keys())          # ['5th', '6th', '7th']
    n_tests = len(tests)
    modes = ['OpenAI Search', 'Custom Search', 'CVE-based Search']
    n_modes = len(modes)

    bar_width = 0.25
    x = np.arange(n_modes)

    for t_index, logs_set in enumerate(tests):
        offset = bar_width * (t_index - (n_tests - 1) / 2)  # centers 3 tests

        for m_index, mode in enumerate(modes):
            enabled_val = data_dict[logs_set][0][m_index]     # bottom bars
            disabled_val = data_dict[logs_set][1][m_index]    # top bars
            xpos = x[m_index] + offset

            # Bottom: early stop enabled — lighter color + enabled hatching
            ax.bar(
                xpos,
                enabled_val,
                bar_width,
                color=colors_enabled[mode],
                edgecolor="black",
                linewidth=1.5,
                hatch=patterns_enabled[logs_set],
            )

            # Top: early stop disabled — stronger color + disabled hatching
            ax.bar(
                xpos,
                disabled_val,
                bar_width,
                bottom=enabled_val,
                color=colors_disabled[mode],
                edgecolor="black",
                linewidth=1.5,
                hatch=patterns_disabled[logs_set],
            )

    # Axes & formatting
    ax.set_ylabel("Vulnerable Environments Generated (%)")
    ax.set_yticks(range(0, 101, 10))
    ax.set_yticklabels(range(0, 101, 10))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f"{y:.0f}%"))
    ax.set_xticks(x)
    ax.set_xticklabels(modes)
    ax.set_ylim(0, 100)
    ax.grid(True, axis="y", linestyle="--", alpha=0.7)

    # Legend — explains hatch patterns only
    legend_elements = []
    for t, r in zip(tests, ['1st', '2nd', '3rd']):
        legend_elements.append(
            Patch(facecolor="white", edgecolor="black",
                hatch=patterns_enabled[t],
                label=f"{r} Test (Early Stop Enabled)")
        )
    for t, r in zip(tests, ['1st', '2nd', '3rd']):
        legend_elements.append(
            Patch(facecolor="white", edgecolor="black",
                hatch=patterns_disabled[t],
                label=f"{r} Test (Early Stop Disabled)")
        )

    ax.legend(
        handles=legend_elements,
        bbox_to_anchor=(0.5, 1.125),
        loc='center',
        ncols=2,
        frameon=False,
        columnspacing=0.8,
        handletextpad=0.4,
        handleheight=1.0,
        handlelength=1.5,
    )
    plt.show()
vul_ass_multirun_ablation_study()
