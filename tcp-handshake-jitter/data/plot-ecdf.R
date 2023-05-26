require(ggplot2)
require(tikzDevice)

args <- commandArgs(trailingOnly = TRUE)
input_file <- args[1]
data <- read.csv(input_file, header = TRUE)
output_prefix <- "tcp-handshake-rtt-ecdf"

tikz(file = paste(output_prefix, ".tex", sep = ""),
     standAlone = FALSE,
     width = 2.2,
     height = 1.8)

# Turn microseconds into milliseconds.
data$ms = data$us/1000

for (p in unique(data$Platform)) {
    s <- subset(data, Platform == p)
    print(sprintf("Median of %s: %f", p, median(s$ms)))
    print(sprintf("Min. of %s: %f", p, min(s$ms)))
}

ggplot(data, aes(x = ms)) +
       stat_ecdf() +
       #scale_x_continuous(limits = c(85, max(data$ms))) +
       theme_minimal() +
       labs(x = "TCP handshake RTT (ms)",
            y = "Empirical CDF")

dev.off()
ggsave(paste(output_prefix, ".pdf", sep = ""))
