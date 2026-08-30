import array
import random
import shutil
import threading
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Callable, List, Optional, Union

@dataclass(frozen=True)
class ScrambleConfig:
    """Configuration for text scrambling animation."""
    text: str = ''
    speed: float = 1.0
    seed: int = 1
    step: int = 1
    tick: int = 1
    scramble: int = 3
    chance: float = 1.0
    overflow: bool = False
    range: Union[List[int], tuple[int, int]] = (65, 125)
    overdrive: Union[bool, int] = False
    ignore: frozenset[str] = frozenset({' '})
    play_on_mount: bool = True
    on_animation_start: Optional[Callable] = None
    on_animation_frame: Optional[Callable[[str], None]] = None
    on_animation_end: Optional[Callable] = None

class TextScrambler:
    """
    Optimized Python implementation of text scrambling animation.
    """
    __slots__ = ('config', 'step_count', 'control', '_running', '_animation_thread', '_char_cache', '_resolved_positions', '_print_lock', 'control_lock')

    def __init__(self, config: ScrambleConfig):
        self.config = config
        random.seed(self.config.seed)
        self._char_cache = array.array('u', [chr(random.randint(config.range[0], config.range[1])) for _ in range(1024)])
        self._running = False
        self._animation_thread = None
        self._resolved_positions: List[int] = []
        self._print_lock = threading.Lock()
        self.control_lock = threading.Lock()
        self._reset()

    def _reset(self):
        """Reset scramble controls."""
        self.step_count = 0
        text_len = len(self.config.text)
        self.control = array.array('i', [self.config.scramble] * text_len)
        self._resolved_positions = []

    @lru_cache(maxsize=128)
    def _get_random_char(self, seed: int) -> str:
        """Get a cached random character."""
        return self._char_cache[seed & 1023]

    def _step_forward(self):
        """Progress scramble state."""
        text_len = len(self.config.text)
        next_pos = len(self._resolved_positions)
        if next_pos < text_len:
            self._resolved_positions.append(next_pos)
            if next_pos == 0:
                control_value = self.config.scramble
            else:
                with self.control_lock:
                    prev_control = self.control[next_pos - 1]
                control_value = max(prev_control - 1, 0)
            with self.control_lock:
                self.control[next_pos] = control_value

    def _draw(self) -> str:
        """Generate current frame of the animation."""
        text = self.config.text
        text_len = len(text)
        result = [' '] * text_len
        with self.control_lock:
            current_control = list(self.control)
        for i in range(text_len):
            if text[i] in self.config.ignore:
                result[i] = text[i]
                continue
            if i in self._resolved_positions:
                if current_control[i] > 0:
                    result[i] = self._get_random_char(self.step_count + i)
                    with self.control_lock:
                        self.control[i] -= 1
                        updated_control = self.control[i]
                    if updated_control == 0:
                        pass
                else:
                    result[i] = text[i]
            else:
                result[i] = self._get_random_char(self.step_count + i)
        result_text = ''.join(result)
        with self.control_lock:
            is_complete = len(self._resolved_positions) == text_len and all((c <= 0 for c in self.control))
        if is_complete:
            result_text = text
            if self.config.on_animation_frame:
                self.config.on_animation_frame(result_text)
            if self.config.on_animation_end:
                self.config.on_animation_end()
            self._running = False
        elif self.config.on_animation_frame:
            self.config.on_animation_frame(result_text)
        with self.control_lock:
            if not all((self.control[i] <= self.control[i - 1] for i in range(1, text_len))):
                with self._print_lock:
                    pass
        return result_text

    def _animate(self):
        """Optimized animation loop."""
        if not self.config.speed:
            return
        fps_interval = 1.0 / (60 * self.config.speed)
        last_frame_time = time.monotonic()
        max_steps = len(self.config.text) * self.config.scramble
        while self._running and self.step_count < max_steps:
            current_time = time.monotonic()
            elapsed = current_time - last_frame_time
            if elapsed > fps_interval:
                last_frame_time = current_time
                if self.step_count % self.config.tick == 0:
                    self._step_forward()
                self._draw()
            else:
                sleep_time = max(0, fps_interval - elapsed)
                if sleep_time > 0.001:
                    time.sleep(sleep_time)
            self.step_count += 1
        if self._running:
            with self.control_lock:
                self.control[:] = array.array('i', [0] * len(self.control))
            self._draw()
            if self.config.on_animation_end:
                self.config.on_animation_end()
            self._running = False

    def play(self):
        """Start the scramble animation."""
        if self._animation_thread and self._animation_thread.is_alive():
            self.stop()
        self._reset()
        self._running = True
        if self.config.on_animation_start:
            self.config.on_animation_start()
        self._animation_thread = threading.Thread(target=self._animate, daemon=True)
        self._animation_thread.start()

    def stop(self):
        """Stop the scramble animation."""
        self._running = False
        if self._animation_thread:
            self._animation_thread.join(timeout=0.1)

def scramble_print(text: str, **config_overrides):
    """
    Run the scrambler in parallel on every line of the input string.
    This allows multiline outputs or ASCII art to be printed with the scramble effect.
    """
    lines = text.split('\n')
    terminal_width = shutil.get_terminal_size().columns
    current_frames = [''] * len(lines)
    active_scramblers = []
    done = threading.Event()
    lock = threading.Lock()

    def redraw_all():
        print('\x1b[H', end='', flush=True)
        print('\x1b[J', end='', flush=True)
        for frame in current_frames:
            print(frame, flush=True)

    def check_completion():
        if all((not scrambler._running for scrambler in active_scramblers)):
            done.set()
            redraw_all()

    def on_frame_factory(idx):

        def on_frame(line_text):
            with lock:
                display_text = line_text[:terminal_width] if not config_overrides.get('overflow', False) else line_text
                current_frames[idx] = display_text
                redraw_all()
                check_completion()
        return on_frame

    def on_end_factory(idx, final_text):

        def on_end():
            with lock:
                current_frames[idx] = final_text
                redraw_all()
                check_completion()
        return on_end
    for i, line in enumerate(lines):
        if not line.strip():
            current_frames[i] = line
            continue
        base_config = ScrambleConfig(text=line)
        conf_dict = dict(base_config.__dict__)
        conf_dict.update(config_overrides)
        conf_dict['on_animation_frame'] = on_frame_factory(i)
        conf_dict['on_animation_end'] = on_end_factory(i, line)
        line_config = ScrambleConfig(**conf_dict)
        s = TextScrambler(line_config)
        active_scramblers.append(s)
    print('\x1b[2J', end='', flush=True)
    redraw_all()
    for s in active_scramblers:
        s.play()
    try:
        while not done.wait(timeout=0.1):
            if not any((s._running for s in active_scramblers)):
                done.set()
                break
    except KeyboardInterrupt:
        for s in active_scramblers:
            s.stop()
    finally:
        for s in active_scramblers:
            s.stop()
        with lock:
            for i, line in enumerate(lines):
                if line.strip():
                    current_frames[i] = line
            redraw_all()
SCRAMBLE_TEXT = '                               __  _    ____  ___\n   ____ ___  ____  _________  / /_| |  / /  |/  /\n  / __ `__ \\/ __ \\/ ___/ __ \\/ __ \\ | / / /|_/ /\n / / / / / / /_/ / /  / /_/ / / / / |/ / /  / /\n/_/ /_/ /_/\\____/_/  / .___/_/ /_/|___/_/  /_/\n                    /_/\n'
