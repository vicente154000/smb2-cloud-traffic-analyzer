import pyshark
import threading
import time
import asyncio

class PysharkUtils:
    """
    Helper para gestionar los hilos que permiten iniciar y detener el análisis de tráfico mediante PyShark.
    """
      
    def __init__(self, interface: str, timeout: int, bpf_filter: str = None):
      self.interface = interface
      self.timeout = timeout
      self.bpf_filter = bpf_filter
	

    def capture_async(self, output_file):

        started_event = threading.Event()
        stop_event = threading.Event()

        # Thread calls function:
        thread = threading.Thread(
            target=self._capture,
            args=(output_file, self.bpf_filter, self.timeout, started_event, stop_event),
            daemon=True
        )
    
        thread.start()
        
        # Wait for the capture to begin:
        while not started_event.is_set():
            print("[Main] Network capture pending...")
            time.sleep(0.1)
        
        print("[Main] Capture started in background thread.")

        return thread, stop_event

    @staticmethod
    async def stop(thread, stop_event):
        """Signal capture thread to stop early."""
        print("[Main] Signaling capture to stop...")
        stop_event.set()
        PysharkUtils.wait(thread)
    

    @staticmethod
    async def wait(thread):
        """Wait for the capture thread to finish (if running)."""
        if thread:
            thread.join()

        print("Capture thread finished.")
        

    # Start capture of newtork traffic:
    def _capture(self, output_file, bpf_filter, timeout: int, started_event: threading.Event, stop_event: threading.Event):

        
        #capture = pyshark.LiveCapture(interface=self.interface, bpf_filter=bpf_filter, output_file=output_file)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            with pyshark.LiveCapture(
                interface=self.interface,
                bpf_filter=bpf_filter,
                output_file=output_file
            ) as capture:
                lastCapture = capture
                capture.set_debug()

                start_time = time.time()
                print(f"Started capture on {self.interface} at {start_time}")
                started_event.set()
                for pkt in capture:

                    if stop_event.is_set():
                        print("[Thread] Stop event detected — stopping capture.")
                        break

                    if timeout and (time.time() - start_time) >= timeout:
                        print("[Thread] Timeout reached — stopping capture.")
                        break

        except Exception as e:
            print(f"[Thread] Capture error: {e}")
        finally:
            #if capture:
            #    capture.close()
            print(f"[Thread] Capture stopped. Saved to {output_file}")

       

# Example usage:
if __name__ == "__main__":

    pktCapture = PysharkUtils(interface='enp0s31f6', timeout=20, bpf_filter=None)

    # Start capture in background
    thread, stop_event = pktCapture.capture_async(output_file='../data/capture.pcap')

    # Wait until capture finishes
    print("Doing other work while capturing...")
    time.sleep(5)
    PysharkUtils.stop(thread, stop_event)






