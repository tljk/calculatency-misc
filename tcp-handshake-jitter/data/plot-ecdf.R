require(ggplot2)
require(tikzDevice)
require(scales) # for "labels=comma"
require(gridExtra) # for side-by-side charts

args <- commandArgs(trailingOnly = TRUE)
input_file <- args[1]
data <- read.csv(input_file, header = TRUE)
output_prefix <- "tcp-handshake-rtt"

tikz(file = paste(output_prefix, ".tex", sep = ""),
     standAlone = FALSE,
     width = 2.3,
     height = 1.8)

# Turn microseconds into milliseconds.
data$ms = data$us/1000

for (p in unique(data$Platform)) {
    s <- subset(data, Platform == p)
    print(p)
    print(quantile(s$ms, c(.99, .999, .9999)))
    print(median(s$ms))
}

ggplot(data, aes(x = ms,
                 color = Platform,
                 linetype = Platform)) +
       stat_ecdf(linewidth = 0.8) +
       scale_color_brewer(palette = "Dark2") +
       scale_x_continuous(labels = comma,
                          trans = "log10") +
       theme_minimal(base_size = 10) +
       theme(legend.position = c(.55,.48),
             legend.background = element_rect(fill = "white",
                                              color = "grey90")) +
       labs(x = "Latency in ms (log)",
            y = "ECDF")

ggsave("myplot.pdf")

dev.off()
