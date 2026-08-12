# Reference data from the original integration

These two files are **copies from the `jfl_active` integration** by Carlos Jose Fernandes,
<https://github.com/fernac03/JFL_ACTIVE>, kept here as test data. See [AUTHORS.md](../../AUTHORS.md).

They are not used by the integration at runtime. They exist so two regression tests keep working
now that this project lives in its own repository:

| File | Used by | Why it must not be dropped |
|---|---|---|
| `legacy_contact_id.yaml` | `test_contact_id.py` | The original table's 84 codes were built from the panel manual by hand and are correct. `contact_id.py` must never lose one of them, and this file is what proves it. It is also one of the two independent sources that confirmed the column alignment of the manual's table — see [contact-id.md](../../docs/protocol/contact-id.md) |
| `legacy_manifest.json` | `test_manifest.py` | Asserts the two integrations keep **different domains**. That is what lets `jfl_active` go on running the user's house while `jfl_alarm` is developed and validated on the same Home Assistant |

Do not edit them. They are a record of the original work, not ours to change.
