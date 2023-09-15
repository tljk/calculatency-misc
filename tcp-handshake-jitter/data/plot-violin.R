require(ggplot2)
require(tikzDevice)
require(scales) # for "labels=comma"

args <- commandArgs(trailingOnly = TRUE)
input_file <- args[1]
data <- read.csv(input_file, header = TRUE)
output_prefix <- "tcp-handshake-rtt"

tikz(file = paste(output_prefix, ".tex", sep = ""),
     standAlone = FALSE,
     width = 3.1,
     height = 1)

# Turn microseconds into milliseconds.
data$ms = data$us/1000

for (p in unique(data$Platform)) {
    s <- subset(data, Platform == p)
    print(sprintf("Median of %s: %f", p, median(s$ms)))
    print(sprintf("Min. of %s: %f", p, min(s$ms)))
}

ggplot(data, aes(x = ms,
                 y = Platform)) +
       geom_violin() +
       #scale_x_continuous(limits = c(75, max(data$ms))) +
       scale_x_continuous(labels=comma, trans="log10") +
       theme_minimal() +
       labs(x = "TCP handshake RTT (ms)",
            y = NULL)

dev.off()
ggsave(paste(output_prefix, ".pdf", sep = ""))
