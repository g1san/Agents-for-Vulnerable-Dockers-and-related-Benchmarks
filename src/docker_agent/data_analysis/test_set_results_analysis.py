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
from data_processing import get_test_set_data

def test_set_model_performance_comparison():
    df = pd.concat([
        get_test_set_data(model="GPT-4o", logs_set="1st"),
        get_test_set_data(model="GPT-4o", logs_set="2nd"),
        get_test_set_data(model="GPT-4o", logs_set="3rd"),
        get_test_set_data(model="gpt-oss-120b", logs_set="1st"),
        get_test_set_data(model="gpt-oss-120b", logs_set="2nd"),
        get_test_set_data(model="gpt-oss-120b", logs_set="3rd"),
    ])

    data_dict = {}
    for model, model_df in df.groupby("model"):
        data_dict[model] = [[0, 0, 0], [0, 0, 0]]
        for cve, cve_model_df in model_df.groupby("cve_id"):
            ig_ok = cve_model_df['hard_service'] & cve_model_df['hard_version'] & cve_model_df['soft_services']
            if len((cve_model_df[ig_ok])) > 0:
                data_dict[model][0][0] += 1
                
            eg_ok = cve_model_df["docker_builds"] & cve_model_df["docker_runs"] & cve_model_df["code_hard_version"] & cve_model_df["network_setup"]
            if len((cve_model_df[ig_ok & eg_ok])) > 0:
                data_dict[model][0][1] += 1
            elif len((cve_model_df[eg_ok])) > 0:
                data_dict[model][1][1] += 1
                
            va_ok = cve_model_df["docker_scout_vulnerable"]
            if len((cve_model_df[ig_ok & eg_ok & va_ok])) > 0:
                data_dict[model][0][2] += 1
            elif len((cve_model_df[eg_ok & va_ok])) > 0:
                data_dict[model][1][2] += 1

    display(data_dict)

    # Tasks (modes) for legend
    modes = ['Information Gathering Task', 'Environment Generation Task', 'Vulnerability Assessment Task']

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

    # Define color scheme - lighter shades for no ablation, darker for with ablation
    colors_no_ablation = {
    'Information Gathering Task': '#FF994C',   
    'Environment Generation Task': '#D9A6FF',  
    'Vulnerability Assessment Task': '#FFEB80'
    }

    colors_with_ablation = {
    'Information Gathering Task': '#FF994C',  
    'Environment Generation Task': '#E8CFFF',
    'Vulnerability Assessment Task': '#FFF5B3' 
    }

    # Define patterns for bars - different for no ablation vs with ablation
    patterns_no_ablation = {
        'Information Gathering Task': '--',
        'Environment Generation Task': '\\\\',
        'Vulnerability Assessment Task': '//'
    }

    patterns_with_ablation = {
        'Information Gathering Task': '++',
        'Environment Generation Task': '//',
        'Vulnerability Assessment Task': '\\\\'
    }

    # Create figure
    fig, ax = plt.subplots(figsize=(6, 5.5))

    # Prepare data for plotting
    grade_levels = list(data_dict.keys())
    n_grades = len(grade_levels)
    n_modes = len(modes)

    # Set width of bars and positions
    bar_width = 0.25
    x = np.arange(n_grades)

    # Plot stacked bars for each mode
    bars_list = []
    for i, mode in enumerate(modes):
        # Get no ablation values (bottom of stack)
        no_ablation = [data_dict[grade][0][i] for grade in grade_levels]
        # Get with ablation values (top of stack)
        with_ablation = [data_dict[grade][1][i] for grade in grade_levels]
        
        offset = bar_width * (i - 1)
        
        # Plot bottom bars (no ablation) - with no hatch pattern and lighter color
        bars_bottom = ax.bar(x + offset, no_ablation, bar_width, 
                    color=colors_no_ablation[mode], 
                    edgecolor='black',
                    linewidth=1.5,
                    hatch=patterns_no_ablation[mode])
        
        # Plot top bars (with ablation) - stacked on top with hatch pattern and darker color
        bars_top = ax.bar(x + offset, with_ablation, bar_width,
                    bottom=no_ablation,
                    color=colors_with_ablation[mode], 
                    edgecolor='black',
                    linewidth=1.5,
                    hatch=patterns_with_ablation[mode])
        
        bars_list.append(bars_bottom)
        
        # Add value labels in the center of bottom bars
        # if mode != 'Information Gathering Task':
        #     for j in range(n_grades):
        #         if no_ablation[j] > 0:
        #             ax.text(j + offset, no_ablation[j] / 2, f'{no_ablation[j]:.0f}%',
        #                 ha='center', va='center', bbox=dict(facecolor='white', edgecolor='none', pad=1))
        
        # Add total labels on top of each bar
        # for j in range(n_grades):
        #     total = no_ablation[j] + with_ablation[j]
        #     ax.text(j + offset, total + 1, f'{total:.0f}%',
        #         ha='center', va='bottom', bbox=dict(facecolor='white', edgecolor='none', pad=1))

    # Customize plot
    ax.set_ylabel('Success Rate (%)')
    ax.set_yticks(range(0, 101, 10))
    ax.set_yticklabels(range(0, 101, 10))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f"{y:.0f}%"))
    ax.set_xticks(x)
    ax.set_xticklabels(["GPT-4o", "gpt-oss:120B"])
    ax.set_ylim(0, 100)
    ax.grid(True, axis="y", linestyle="--", alpha=0.7)

    # Create custom legend differentiating ablation conditions
    legend_elements = [
        Patch(facecolor=colors_no_ablation['Information Gathering Task'], hatch=patterns_no_ablation['Information Gathering Task'], 
            label='Information Gathering Task', edgecolor='black', linewidth=1.5),
        Patch(facecolor=colors_no_ablation['Environment Generation Task'], hatch=patterns_no_ablation['Environment Generation Task'], 
            label='Environment Generation Task (Validated Information Runs)', edgecolor='black', linewidth=1.5),
        Patch(facecolor=colors_no_ablation['Vulnerability Assessment Task'], hatch=patterns_no_ablation['Vulnerability Assessment Task'], 
            label='Vulnerability Assessment Task (Validated Information Runs)', edgecolor='black', linewidth=1.5),
        Patch(facecolor=colors_with_ablation['Environment Generation Task'], hatch=patterns_with_ablation['Environment Generation Task'], 
            label='Environment Generation Task (Incorrect Information Runs)', edgecolor='black', linewidth=1.5),
        Patch(facecolor=colors_with_ablation['Vulnerability Assessment Task'], hatch=patterns_with_ablation['Vulnerability Assessment Task'], 
            label='Vulnerability Assessment Task (Incorrect Information Runs)', edgecolor='black', linewidth=1.5)
    ]

    # Add legend above the plot
    ax.legend(handles=legend_elements,
            bbox_to_anchor=(0.5, 1.2),
            loc='center',
            ncols=1,
            columnspacing=0.5,
            handletextpad=0.3,
            handleheight=1.2,
            handlelength=1.8,
            frameon=False,
            title='Agentic Workflow Tasks',)

    plt.tight_layout()
    plt.show() 
test_set_model_performance_comparison()



def test_set_model_combined_performance_comparison():
    df = pd.concat([
        get_test_set_data(model="GPT-4o", logs_set="1st"),
        get_test_set_data(model="GPT-4o", logs_set="2nd"),
        get_test_set_data(model="GPT-4o", logs_set="3rd"),
        get_test_set_data(model="gpt-oss-120b", logs_set="1st"),
        get_test_set_data(model="gpt-oss-120b", logs_set="2nd"),
        get_test_set_data(model="gpt-oss-120b", logs_set="3rd"),
    ])

    data_dict = {}
    for model, model_df in df.groupby("model"):
        data_dict[model] = [[0, 0, 0], [0, 0, 0]]
        for cve, cve_model_df in model_df.groupby("cve_id"):
            ig_ok = cve_model_df['hard_service'] & cve_model_df['hard_version'] & cve_model_df['soft_services']
            if len((cve_model_df[ig_ok])) > 0:
                data_dict[model][0][0] += 1
                
            eg_ok = cve_model_df["docker_builds"] & cve_model_df["docker_runs"] & cve_model_df["code_hard_version"] & cve_model_df["network_setup"]
            if len((cve_model_df[ig_ok & eg_ok])) > 0:
                data_dict[model][0][1] += 1
            elif len((cve_model_df[eg_ok])) > 0:
                data_dict[model][1][1] += 1
                
            va_ok = cve_model_df["docker_scout_vulnerable"]
            if len((cve_model_df[ig_ok & eg_ok & va_ok])) > 0:
                data_dict[model][0][2] += 1
            elif len((cve_model_df[eg_ok & va_ok])) > 0:
                data_dict[model][1][2] += 1

    display(data_dict)

    # Tasks (modes) for legend
    modes = ['Information Gathering Task', 'Environment Generation Task', 'Vulnerability Assessment Task']

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

    # Define color scheme - lighter shades for no ablation, darker for with ablation
    colors_no_ablation = {
    'Information Gathering Task': '#FF994C',   
    'Environment Generation Task': '#D9A6FF',  
    'Vulnerability Assessment Task': '#FFEB80'
    }

    colors_with_ablation = {
    'Information Gathering Task': '#FF994C',  
    'Environment Generation Task': '#E8CFFF',
    'Vulnerability Assessment Task': '#FFF5B3' 
    }

    # Define patterns for bars - different for no ablation vs with ablation
    patterns_no_ablation = {
        'Information Gathering Task': '--',
        'Environment Generation Task': '\\\\',
        'Vulnerability Assessment Task': '//'
    }

    patterns_with_ablation = {
        'Information Gathering Task': '++',
        'Environment Generation Task': '//',
        'Vulnerability Assessment Task': '\\\\'
    }

    # Create figure
    fig, ax = plt.subplots(figsize=(6, 5.5))

    # Prepare data for plotting
    grade_levels = list(data_dict.keys())
    n_grades = len(grade_levels)
    n_modes = len(modes)

    # Set width of bars and positions
    bar_width = 0.25
    x = np.arange(n_grades)

    # Plot stacked bars for each mode
    bars_list = []
    for i, mode in enumerate(modes):
        # Get no ablation values (bottom of stack)
        no_ablation = [data_dict[grade][0][i] for grade in grade_levels]
        # Get with ablation values (top of stack)
        with_ablation = [data_dict[grade][1][i] for grade in grade_levels]
        
        offset = bar_width * (i - 1)
        
        # Plot bottom bars (no ablation) - with no hatch pattern and lighter color
        bars_bottom = ax.bar(x + offset, no_ablation, bar_width, 
                    color=colors_no_ablation[mode], 
                    edgecolor='black',
                    linewidth=1.5,
                    hatch=patterns_no_ablation[mode])
        
        # Plot top bars (with ablation) - stacked on top with hatch pattern and darker color
        bars_top = ax.bar(x + offset, with_ablation, bar_width,
                    bottom=no_ablation,
                    color=colors_with_ablation[mode], 
                    edgecolor='black',
                    linewidth=1.5,
                    hatch=patterns_with_ablation[mode])
        
        bars_list.append(bars_bottom)
        
        # Add value labels in the center of bottom bars
        # if mode != 'Information Gathering Task':
        #     for j in range(n_grades):
        #         if no_ablation[j] > 0:
        #             ax.text(j + offset, no_ablation[j] / 2, f'{no_ablation[j]:.0f}%',
        #                 ha='center', va='center', bbox=dict(facecolor='white', edgecolor='none', pad=1))
        
        # Add total labels on top of each bar
        # for j in range(n_grades):
        #     total = no_ablation[j] + with_ablation[j]
        #     ax.text(j + offset, total + 1, f'{total:.0f}%',
        #         ha='center', va='bottom', bbox=dict(facecolor='white', edgecolor='none', pad=1))

    # Customize plot
    ax.set_ylabel('Success Rate (%)')
    ax.set_yticks(range(0, 101, 10))
    ax.set_yticklabels(range(0, 101, 10))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f"{y:.0f}%"))
    ax.set_xticks(x)
    ax.set_xticklabels(["GPT-4o", "gpt-oss:120B"])
    ax.set_ylim(0, 100)
    ax.grid(True, axis="y", linestyle="--", alpha=0.7)

    # Create custom legend differentiating ablation conditions
    legend_elements = [
        Patch(facecolor=colors_no_ablation['Information Gathering Task'], hatch=patterns_no_ablation['Information Gathering Task'], 
            label='Information Gathering Task', edgecolor='black', linewidth=1.5),
        Patch(facecolor=colors_no_ablation['Environment Generation Task'], hatch=patterns_no_ablation['Environment Generation Task'], 
            label='Environment Generation Task (Validated Information Runs)', edgecolor='black', linewidth=1.5),
        Patch(facecolor=colors_no_ablation['Vulnerability Assessment Task'], hatch=patterns_no_ablation['Vulnerability Assessment Task'], 
            label='Vulnerability Assessment Task (Validated Information Runs)', edgecolor='black', linewidth=1.5),
        Patch(facecolor=colors_with_ablation['Environment Generation Task'], hatch=patterns_with_ablation['Environment Generation Task'], 
            label='Environment Generation Task (Incorrect Information Runs)', edgecolor='black', linewidth=1.5),
        Patch(facecolor=colors_with_ablation['Vulnerability Assessment Task'], hatch=patterns_with_ablation['Vulnerability Assessment Task'], 
            label='Vulnerability Assessment Task (Incorrect Information Runs)', edgecolor='black', linewidth=1.5)
    ]

    # Add legend above the plot
    ax.legend(handles=legend_elements,
            bbox_to_anchor=(0.5, 1.2),
            loc='center',
            ncols=1,
            columnspacing=0.5,
            handletextpad=0.3,
            handleheight=1.2,
            handlelength=1.8,
            frameon=False,
            title='Agentic Workflow Tasks',)

    plt.tight_layout()
    plt.show() 
test_set_model_combined_performance_comparison()
