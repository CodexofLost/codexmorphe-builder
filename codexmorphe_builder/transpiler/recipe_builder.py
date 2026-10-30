import json
from typing import Any, Dict, List, Optional
from ..parser.compatibility import DiscoveredApp


def generate_hook_recipe_json(pkg: str, app_info: DiscoveredApp) -> str:
    """
    Generate the dynamic hooks.json manifest for a given application.
    Combines core high-impact community recipes with transpiled patch definitions.
    """
    hooks: List[Dict[str, Any]] = []

    # 1. Application-specific standard bytecode hook recipes
    if pkg == "com.google.android.youtube":
        hooks.extend([
            {
                "id": "hide_video_ads",
                "name": "Hide ads",
                "action": "CONSTANT_REPLACE",
                "constant_val": "void",
                "fingerprint": {
                    "return_type": "V",
                    "opcodes": ["const/4", "if-eqz", "iget-object", "if-nez", "iget", "const/4", "if-ne", "iget-object"]
                }
            },
            {
                "id": "background_playback",
                "name": "Remove background playback restrictions",
                "action": "CONSTANT_REPLACE",
                "constant_val": True,
                "fingerprint": {
                    "return_type": "Z",
                    "param_types": ["L"],
                    "opcodes": ["const/4", "if-eqz", "iget", "and-int/lit16", "if-eqz", "iget-object"]
                }
            },
            {
                "id": "shorts_background_playback",
                "name": "Remove background playback restrictions",
                "action": "CONSTANT_REPLACE",
                "constant_val": True,
                "fingerprint": {
                    "return_type": "Z",
                    "param_types": ["L"],
                    "literal": 151635310
                }
            },
            {
                "id": "settings_hook",
                "name": "Settings",
                "action": "METHOD_REPLACE",
                "extension_call": "app.morphe.extension.youtube.settings.YouTubeActivityHook->initialize(Landroid/app/Activity;)V",
                "fingerprint": {
                    "declaring_class_ends_with": ".LicenseActivity",
                    "method_name": "onCreate"
                }
            }
        ])

    elif pkg == "com.instagram.android":
        hooks.extend([
            {
                "id": "hide_ads",
                "name": "Hide ads",
                "action": "CONSTANT_REPLACE",
                "constant_val": False,
                "fingerprint": {
                    "strings": ["Is ad pod"]
                }
            }
        ])

    elif pkg == "com.google.android.apps.youtube.music":
        hooks.extend([
            {
                "id": "background_playback",
                "name": "Remove background playback restrictions",
                "action": "CONSTANT_REPLACE",
                "constant_val": True,
                "fingerprint": {
                    "return_type": "Z",
                    "param_types": ["L"]
                }
            }
        ])

    elif pkg == "com.reddit.frontpage":
        hooks.extend([
            {
                "id": "hide_ads",
                "name": "Hide ads",
                "action": "CONSTANT_REPLACE",
                "constant_val": False,
                "fingerprint": {
                    "strings": ["is_promoted"]
                }
            }
        ])

    elif pkg == "com.twitter.android":
        hooks.extend([
            {
                "id": "hide_ads",
                "name": "Hide ads",
                "action": "CONSTANT_REPLACE",
                "constant_val": False,
                "fingerprint": {
                    "strings": ["promoted_content"]
                }
            }
        ])

    manifest = {
        "version": 1,
        "package_name": pkg,
        "hooks": hooks
    }

    return json.dumps(manifest, indent=2)
