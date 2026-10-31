## Legal

**You are responsible for where you point this. The author is not.**

phpomni is active. It uploads files, writes `.htaccess` and `.user.ini`, sends POST bodies to unknown endpoints, and can leave a webshell sitting on a server. None of that is guaranteed to be harmless, reversible, or noticed. If a site breaks after a run, that is on the operator, not on this repo.

**No warranty, no liability.** The software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the author or copyright holder be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or the use or other dealings in the software.

**Specifically, the author accepts no responsibility for:**

- Testing a target without permission
- Data loss, corruption, or downtime caused by a run
- An overwritten or broken `.htaccess`
- A webshell left behind and later found — or later exploited by someone else
- Credentials, tokens, or customer data captured into `loot/`
- Terms-of-service violations on hosted platforms (shared hosting, WordPress.com, Shodan's API)
- Legal exposure in any jurisdiction, including under computer-misuse statutes
- Anything a third party does after being handed the output

**Practical risk levels**, so you can judge before you run:

| Mode | Touches | Risk |
|---|---|---|
| `--plan` | Nothing | None — no requests beyond one GET |
| `--no-upload --no-lfi` | Nothing | Read-only |
| default | Uploads files to writable dirs | Low, leaves artefacts |
| `--config-upload` | Rewrites `.htaccess` / `.user.ini` | Medium — can break a live site |
| `--pwn` | All of the above, delay 0 | High — loud and persistent |

If a client cares, send them `--plan` output first and get a written yes before the run. Clean up after yourself: the uploaded files are named `phpomni*` and the config lines are `AddType` / `AddHandler` / `auto_prepend_file` — both are easy to spot and remove.

**Scope of authorisation is your problem to establish**, not the tool's to guess. A successful shell is not evidence you were allowed to take one.
