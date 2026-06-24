const processors = new Map();
const jobs = new Map();
let jobCounter = 0;

function generateId(prefix = 'job') {
  jobCounter += 1;
  return `${prefix}_${Date.now()}_${jobCounter}`;
}

function registerProcessor(queueName, processor) {
  processors.set(queueName, processor);
}

async function executeJob(queueName, job) {
  const processor = processors.get(queueName);
  if (!processor) {
    throw new Error(`No processor registered for queue "${queueName}"`);
  }

  const attempts = job.opts.attempts || 1;
  const backoff = job.opts.backoff?.delay || 0;

  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      job.attemptsMade = attempt;
      job.state = 'active';
      const result = await processor(job.data, job);
      job.state = 'completed';
      job.returnvalue = result;
      jobs.set(job.id, job);
      return job;
    } catch (error) {
      job.failedReason = error.message;
      job.state = attempt >= attempts ? 'failed' : 'retrying';
      jobs.set(job.id, job);
      if (attempt >= attempts) {
        if (typeof job.opts.onFailed === 'function') {
          try {
            job.opts.onFailed(error, job);
          } catch (callbackError) {
            // Ignore callback errors so the original failure remains visible.
          }
        }
        throw error;
      }
      const delay = backoff * Math.pow(2, attempt - 1);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  return job;
}

async function enqueue(queueName, data, opts = {}) {
  const job = {
    id: generateId(queueName),
    name: queueName,
    data,
    opts: {
      attempts: opts.attempts || 3,
      backoff: {
        type: 'exponential',
        delay: opts.backoff?.delay || 250
      },
      onFailed: opts.onFailed
    },
    state: 'queued',
    attemptsMade: 0,
    createdAt: new Date().toISOString()
  };

  jobs.set(job.id, job);

  setImmediate(() => {
    executeJob(queueName, job).catch(() => {
      // Processor errors are captured on the job object and handled by the caller.
    });
  });

  return job;
}

function getJob(jobId) {
  return jobs.get(jobId);
}

module.exports = {
  enqueue,
  getJob,
  registerProcessor
};
