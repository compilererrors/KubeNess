import kpi_report


def pytest_terminal_summary(terminalreporter):
    kpi_report.summary(terminalreporter)
