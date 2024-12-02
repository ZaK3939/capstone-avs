import { ethers } from 'ethers';
import * as dotenv from 'dotenv';
import * as fs from 'fs';
import * as path from 'path';
dotenv.config();

// Check env
if (!Object.keys(process.env).length) {
  throw new Error('process.env object is empty');
}

// Setup env variables
const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);
const wallet = new ethers.Wallet(process.env.PRIVATE_KEY!, provider);
let chainId = 31337;

// Load deployment data
const avsDeploymentData = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, `../contracts/deployments/hello-world/${chainId}.json`), 'utf8'),
);

const serviceManagerAddress = avsDeploymentData.addresses.helloWorldServiceManager;
const serviceManagerABI = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, '../abis/UniGuardServiceManager.json'), 'utf8'),
);

const serviceManager = new ethers.Contract(serviceManagerAddress, serviceManagerABI, wallet);

// メトリクスタスク生成用の関数
function generateMetricsTaskName(hookAddress: string): string {
  const timestamp = Date.now();
  // 完全なアドレス形式を使用する
  const formattedAddr = ethers.getAddress(hookAddress.padEnd(42, '0'));
  return `metrics_${formattedAddr}_${timestamp}`;
}

async function createMetricsTask(hookAddress: string) {
  try {
    const taskName = generateMetricsTaskName(hookAddress);
    const tx = await serviceManager.createNewTask(taskName);
    const receipt = await tx.wait();
    console.log(`Metrics task created for hook ${hookAddress}, tx: ${receipt.hash}`);
  } catch (error) {
    console.error('Error creating metrics task:', error);
  }
}

// 定期的なメトリクス収集タスクの生成
function startMetricsTasks() {
  const testHookAddress = '0x1234567890123456789012345678901234567890';

  setInterval(() => {
    console.log(`Creating metrics task for hook: ${testHookAddress}`);
    createMetricsTask(testHookAddress);
  }, 24000);
}

startMetricsTasks();
