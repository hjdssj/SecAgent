from time import perf_counter


class AnalysisTimer:
    """
    Measure elapsed analysis time in milliseconds.

    Parameters:
     None

    Returns:
     A lightweight timer for one analysis run

    Raises:
     None
    """

    def __init__(self) -> None:
        """
        Start the timer.

        Parameters:
         None

        Returns:
         None

        Raises:
         None
        """

        self.started_at = perf_counter()

    def elapsed_ms(self) -> float:
        """
        Return elapsed time in milliseconds.

        Parameters:
         None

        Returns:
         Elapsed milliseconds rounded to two decimals

        Raises:
         None
        """

        return round((perf_counter() - self.started_at) * 1000, 2)
