import { ethers } from 'ethers';
import * as dotenv from 'dotenv';
const fs = require('fs');
const path = require('path');
dotenv.config();

// Check env
if (!Object.keys(process.env).length) {
  throw new Error('process.env object is empty');
}

// Debug deployment data loading
console.log('Loading deployment data...');
console.log('Current directory:', __dirname);
console.log(
  'Attempting to load deployment data from:',
  path.resolve(__dirname, '../contracts/deployments/hello-world/31337.json'),
);

// Setup env variables
const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);
const wallet = new ethers.Wallet(process.env.PRIVATE_KEY!, provider);
let chainId = 31337;

// Load deployment data
const avsDeploymentData = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, `../contracts/deployments/hello-world/${chainId}.json`), 'utf8'),
);
console.log('AVS Deployment data:', avsDeploymentData);

const coreDeploymentData = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, `../contracts/deployments/core/${chainId}.json`), 'utf8'),
);
console.log('Core Deployment data:', coreDeploymentData);

// Get contract addresses
const delegationManagerAddress = coreDeploymentData.addresses.delegation;
const avsDirectoryAddress = coreDeploymentData.addresses.avsDirectory;
const serviceManagerAddress = avsDeploymentData.addresses.helloWorldServiceManager;
const ecdsaStakeRegistryAddress = avsDeploymentData.addresses.stakeRegistry;

console.log('Contract addresses:', {
  delegationManager: delegationManagerAddress,
  avsDirectory: avsDirectoryAddress,
  serviceManager: serviceManagerAddress,
  ecdsaStakeRegistry: ecdsaStakeRegistryAddress,
});

// Load ABIs
const delegationManagerABI = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, '../abis/IDelegationManager.json'), 'utf8'),
);

const ecdsaRegistryABI = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, '../abis/ECDSAStakeRegistry.json'), 'utf8'),
);

const serviceManagerABI = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, '../abis/UniGuardServiceManager.json'), 'utf8'),
);

const avsDirectoryABI = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../abis/IAVSDirectory.json'), 'utf8'));

// Initialize contracts
const delegationManager = new ethers.Contract(delegationManagerAddress, delegationManagerABI, wallet);
const serviceManager = new ethers.Contract(serviceManagerAddress, serviceManagerABI, wallet);
const ecdsaRegistryContract = new ethers.Contract(ecdsaStakeRegistryAddress, ecdsaRegistryABI, wallet);
const avsDirectory = new ethers.Contract(avsDirectoryAddress, avsDirectoryABI, wallet);

if (!serviceManagerAddress) {
  console.error('Service manager address is undefined');
  console.log('Available addresses:', avsDeploymentData.addresses);
  throw new Error('Service manager address not found');
}

console.log('Contract addresses:', {
  delegationManager: delegationManagerAddress,
  avsDirectory: avsDirectoryAddress,
  serviceManager: serviceManagerAddress,
  ecdsaStakeRegistry: ecdsaStakeRegistryAddress,
});

// Metrics collection
async function collectMetrics(hookAddress: string) {
  try {
    const blockNumber = await provider.getBlockNumber();
    const block = await provider.getBlock(blockNumber);

    return JSON.stringify({
      hookAddress: hookAddress,
      timestamp: Date.now(),
      blockNumber: blockNumber,
      blockTimestamp: block?.timestamp,
      txCount: 1, // Initial simple implementation
    });
  } catch (error) {
    console.error('Error collecting metrics:', error);
    throw error;
  }
}

function parseHookAddressFromTaskName(taskName: string): string {
  const parts = taskName.split('_');
  if (parts.length < 2) {
    throw new Error(`Invalid task name format: ${taskName}`);
  }
  return parts[1];
}

const signAndRespondToTask = async (taskIndex: number, taskCreatedBlock: number, taskName: string) => {
  try {
    const hookAddress = parseHookAddressFromTaskName(taskName);
    const metrics = await collectMetrics(hookAddress);
    const metricsStr = JSON.stringify(metrics);

    const messageHash = ethers.solidityPackedKeccak256(['string', 'string'], [metricsStr, taskName]);
    const messageBytes = ethers.getBytes(messageHash);
    const signature = await wallet.signMessage(messageBytes);

    const operators = [await wallet.getAddress()];
    const signatures = [signature];
    const signedTask = ethers.AbiCoder.defaultAbiCoder().encode(
      ['address[]', 'bytes[]', 'uint32'],
      [operators, signatures, await provider.getBlockNumber()],
    );

    const tx = await serviceManager.respondToTask(
      { name: taskName, taskCreatedBlock },
      taskIndex,
      signedTask,
      metricsStr,
      { gasLimit: 500000 },
    );

    const receipt = await tx.wait();
    console.log('Transaction hash:', receipt.hash);
  } catch (error) {
    console.error('Error details:', error);
    throw error;
  }
};

const checkOperatorStatus = async () => {
  const isRegistered = await ecdsaRegistryContract.operatorRegistered(wallet.address);
  console.log('Operator registration status:', isRegistered);
  return isRegistered;
};
const registerOperator = async () => {
  console.log('Starting operator registration process...');

  try {
    const tx1 = await delegationManager.registerAsOperator(
      {
        __deprecated_earningsReceiver: await wallet.address,
        delegationApprover: '0x0000000000000000000000000000000000000000',
        stakerOptOutWindowBlocks: 0,
      },
      '',
    );
    const receipt1 = await tx1.wait();
    console.log(`Operator registered to Core EigenLayer contracts in block ${receipt1.blockNumber}`);

    const salt = ethers.hexlify(ethers.randomBytes(32));
    const expiry = Math.floor(Date.now() / 1000) + 3600;

    let operatorSignatureWithSaltAndExpiry = {
      signature: '',
      salt: salt,
      expiry: expiry,
    };

    const operatorDigestHash = await avsDirectory.calculateOperatorAVSRegistrationDigestHash(
      wallet.address,
      await serviceManager.getAddress(),
      salt,
      expiry,
    );

    const operatorSigningKey = new ethers.SigningKey(process.env.PRIVATE_KEY!);
    const operatorSignedDigestHash = operatorSigningKey.sign(operatorDigestHash);
    operatorSignatureWithSaltAndExpiry.signature = ethers.Signature.from(operatorSignedDigestHash).serialized;

    console.log('Registering Operator to AVS Registry contract');

    const tx2 = await ecdsaRegistryContract.registerOperatorWithSignature(
      operatorSignatureWithSaltAndExpiry,
      wallet.address,
    );

    const receipt2 = await tx2.wait();
    console.log(`Operator registered on AVS successfully in block ${receipt2.blockNumber}`);
  } catch (error) {
    console.error('Error in registerOperator:', error);
    throw error;
  }
};

const monitorNewTasks = async () => {
  console.log('Starting task monitoring...');

  serviceManager.on('NewTaskCreated', async (taskIndex: number, task: any) => {
    try {
      console.log(`New task detected: ${task.name} (index: ${taskIndex})`);

      if (task.name.startsWith('metrics_')) {
        console.log(`Processing metrics task ${taskIndex}`);
        await signAndRespondToTask(taskIndex, task.taskCreatedBlock, task.name);
      } else {
        console.log(`Skipping non-metrics task: ${task.name}`);
      }
    } catch (error) {
      console.error(`Error processing task ${taskIndex}:`, error);
    }
  });

  console.log('Monitoring for metrics tasks...');
};

const main = async () => {
  try {
    console.log('Starting UniGuard operator...');

    // オペレーターステータスチェック
    const isRegistered = await checkOperatorStatus();
    if (!isRegistered) {
      await registerOperator();
    }

    await monitorNewTasks();
    console.log('Operator setup completed successfully');
  } catch (error) {
    console.error('Fatal error in main function:', error);
    process.exit(1);
  }
};

main();
