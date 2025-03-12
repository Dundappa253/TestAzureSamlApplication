package job;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.support.CronTrigger;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.ScheduledFuture;

@Service
public class CustomJobSchedulerService {

    @Autowired
    private TaskScheduler taskScheduler;

    @Autowired
    private CustomJobRepository customJobRepository;

    @Autowired
    private JobExecutionLogRepository jobExecutionLogRepository;

    @Autowired
    private JobParameterRepository jobParameterRepository;

    @PostConstruct
    public void scheduleJobs() {
        List<CustomJob> jobs = customJobRepository.findByIsActiveTrue();
        for (CustomJob job : jobs) {
            scheduleJob(job);
        }
    }

    public void scheduleJob(CustomJob job) {
        Runnable task = createTask(job);
        CronTrigger trigger = new CronTrigger(job.getCronExpression());
        ScheduledFuture<?> scheduledFuture = taskScheduler.schedule(task, trigger);
        // Store the scheduledFuture if you need to cancel the job later
    }

    private Runnable createTask(CustomJob job) {
        return () -> {
            JobExecutionLog log = new JobExecutionLog();
            log.setJob(job);
            log.setStartTime(LocalDateTime.now());
            log.setStatus("STARTED");
            jobExecutionLogRepository.save(log);

            try {
                Class<?> clazz = Class.forName(job.getJobClass());
                Runnable jobInstance = (Runnable) clazz.getDeclaredConstructor().newInstance();

                // Pass parameters to the job (if needed)
                if (jobInstance instanceof ParameterizedJob) {
                    List<JobParameter> parameters = jobParameterRepository.findByJobId(job.getId());
                    ((ParameterizedJob) jobInstance).setParameters(parameters);
                }

                jobInstance.run();

                log.setStatus("SUCCESS");
            } catch (Exception e) {
                log.setStatus("FAILED");
                log.setErrorMessage(e.getMessage());
            } finally {
                log.setEndTime(LocalDateTime.now());
                jobExecutionLogRepository.save(log);
            }
        };
    }
}