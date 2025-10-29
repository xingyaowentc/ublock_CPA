#!/usr/bin/env python3
"""
UBlock CPA攻击结果可视化 - Python版本
备选方案，解决Gnuplot渲染问题
"""

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import os

def plot_power_traces():
    """绘制功耗轨迹"""
    try:
        # 读取功耗轨迹数据
        data = pd.read_csv('ublock_cpa_traces.dat', sep=r'\s+', comment='#')
        
        plt.figure(figsize=(12, 8))
        
        # 绘制前6条轨迹
        cols = data.columns[1:7]  # 跳过时间列
        for i, col in enumerate(cols):
            plt.plot(data.iloc[:, 0], data[col], label=f'Trace {i}', linewidth=1.5)
        
        # 标记S盒操作窗口
        plt.axvspan(15, 25, alpha=0.3, color='yellow', label='S-box Window')
        
        plt.xlabel('Time Points')
        plt.ylabel('Power Consumption')
        plt.title('UBlock CPA Attack - Power Traces')
        plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig('ublock_traces_python.png', dpi=300, bbox_inches='tight')
        plt.close()
        print("✅ 功耗轨迹图生成成功: ublock_traces_python.png")
        
    except Exception as e:
        print(f"❌ 功耗轨迹图生成失败: {e}")

def plot_byte_attack():
    """绘制字节级攻击结果"""
    try:
        # 读取字节攻击数据
        data = pd.read_csv('ublock_cpa_byte_attack.dat', sep=r'\s+', comment='#')
        
        plt.figure(figsize=(12, 8))
        
        # 分离正确和错误密钥
        correct_keys = data[data.iloc[:, 3] == 1]  # 第4列是正确密钥标志
        wrong_keys = data[data.iloc[:, 3] == 0]
        
        # 绘制柱状图
        plt.bar(wrong_keys.iloc[:, 0], wrong_keys.iloc[:, 1], 
                color='lightblue', alpha=0.7, label='Wrong Keys', width=0.8)
        plt.bar(correct_keys.iloc[:, 0], correct_keys.iloc[:, 1], 
                color='red', alpha=0.8, label='Correct Key', width=0.8)
        
        plt.xlabel('Key Guess')
        plt.ylabel('Max Correlation')
        plt.title('UBlock CPA Attack - Byte-level Results')
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig('ublock_byte_attack_python.png', dpi=300, bbox_inches='tight')
        plt.close()
        print("✅ 字节攻击图生成成功: ublock_byte_attack_python.png")
        
    except Exception as e:
        print(f"❌ 字节攻击图生成失败: {e}")

def plot_nibble_attack():
    """绘制Nibble级攻击结果"""
    try:
        # 读取nibble攻击数据
        data = pd.read_csv('ublock_cpa_nibble_attack.dat', sep=r'\s+', comment='#')
        
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10))
        
        # 高4位攻击结果
        correct_high = data[data.iloc[:, 3] == 1]  # 第4列是高4位正确标志
        wrong_high = data[data.iloc[:, 3] == 0]
        
        ax1.bar(wrong_high.iloc[:, 0], wrong_high.iloc[:, 1], 
                color='lightgreen', alpha=0.7, label='Wrong High Nibbles', width=0.6)
        ax1.bar(correct_high.iloc[:, 0], correct_high.iloc[:, 1], 
                color='red', alpha=0.8, label='Correct High Nibble', width=0.6)
        
        ax1.set_xlabel('High Nibble Guess (Bits 7-4)')
        ax1.set_ylabel('Max Correlation')
        ax1.set_title('UBlock CPA - High Nibble Attack')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        ax1.set_xlim(-0.5, 15.5)
        
        # 低4位攻击结果
        correct_low = data[data.iloc[:, 4] == 1]  # 第5列是低4位正确标志
        wrong_low = data[data.iloc[:, 4] == 0]
        
        ax2.bar(wrong_low.iloc[:, 0], wrong_low.iloc[:, 2], 
                color='orange', alpha=0.7, label='Wrong Low Nibbles', width=0.6)
        ax2.bar(correct_low.iloc[:, 0], correct_low.iloc[:, 2], 
                color='blue', alpha=0.8, label='Correct Low Nibble', width=0.6)
        
        ax2.set_xlabel('Low Nibble Guess (Bits 3-0)')
        ax2.set_ylabel('Max Correlation')
        ax2.set_title('UBlock CPA - Low Nibble Attack')
        ax2.legend()
        ax2.grid(True, alpha=0.3)
        ax2.set_xlim(-0.5, 15.5)
        
        plt.tight_layout()
        plt.savefig('ublock_nibble_attack_python.png', dpi=300, bbox_inches='tight')
        plt.close()
        print("✅ Nibble攻击图生成成功: ublock_nibble_attack_python.png")
        
    except Exception as e:
        print(f"❌ Nibble攻击图生成失败: {e}")

def plot_sbox_verification():
    """绘制S盒验证图"""
    try:
        # 读取S盒验证数据
        data = pd.read_csv('ublock_sbox_verification.dat', sep=r'\s+', comment='#')
        
        plt.figure(figsize=(10, 6))
        
        # 散点图
        plt.scatter(data.iloc[:, 0], data.iloc[:, 2], 
                   s=100, color='blue', alpha=0.7, label='Measured Data')
        
        # 拟合线
        if len(data) > 1:
            z = np.polyfit(data.iloc[:, 0], data.iloc[:, 2], 1)
            p = np.poly1d(z)
            x_fit = np.linspace(data.iloc[:, 0].min(), data.iloc[:, 0].max(), 100)
            plt.plot(x_fit, p(x_fit), 'r-', linewidth=2, label=f'Linear Fit (slope={z[0]:.3f})')
        
        plt.xlabel('Hamming Weight of S-box Output')
        plt.ylabel('Average Power Consumption')
        plt.title('UBlock S-box Power Leakage Verification')
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig('ublock_sbox_python.png', dpi=300, bbox_inches='tight')
        plt.close()
        print("✅ S盒验证图生成成功: ublock_sbox_python.png")
        
    except Exception as e:
        print(f"❌ S盒验证图生成失败: {e}")

def main():
    """主函数"""
    print("=" * 60)
    print("UBlock CPA攻击结果可视化 - Python版本")
    print("=" * 60)
    
    # 检查数据文件是否存在
    required_files = [
        'ublock_cpa_traces.dat',
        'ublock_cpa_byte_attack.dat',
        'ublock_cpa_nibble_attack.dat',
        'ublock_sbox_verification.dat'
    ]
    
    missing_files = [f for f in required_files if not os.path.exists(f)]
    if missing_files:
        print(f"❌ 缺少数据文件: {missing_files}")
        print("请先运行 UBlock CPA 攻击程序生成数据文件")
        return
    
    # 生成所有图表
    plot_power_traces()
    plot_byte_attack()
    plot_nibble_attack()
    plot_sbox_verification()
    
    print("\n" + "=" * 60)
    print("Python可视化完成！生成的文件:")
    print("📊 ublock_traces_python.png - 功耗轨迹")
    print("📈 ublock_byte_attack_python.png - 字节攻击结果")
    print("📉 ublock_nibble_attack_python.png - Nibble攻击结果")
    print("🔍 ublock_sbox_python.png - S盒验证")
    print("=" * 60)

if __name__ == "__main__":
    main()