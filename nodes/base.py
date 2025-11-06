from abc import ABC
from typing import Any, Dict


class ComfyUICustomNodeBase(ABC):
    """Base class for ComfyUI custom nodes.

    Subclasses must define the following class variables:
    - RETURN_TYPES: Return type tuple
    - RETURN_NAMES: Return name tuple
    - FUNCTION: Execution function name (typically "run")
    - CATEGORY: Node category
    """

    @classmethod
    def INPUT_TYPES(cls) -> Dict[str, Any]:
        """Defines the input types for the node.

        Returns:
            Input type schema dictionary
        """
        return {
            "required": {},
            "optional": {},
        }

    RETURN_TYPES = None
    RETURN_NAMES = None
    FUNCTION = None
    CATEGORY = None

    def __init_subclass__(cls, **kwargs):
        """Validates that required attributes are defined when a subclass is created."""
        super().__init_subclass__(**kwargs)

        # Skip validation for the abstract base class itself
        if cls.__name__ == "ComfyUICustomNodeBase":
            return

        required_attributes = {
            "RETURN_TYPES": cls.RETURN_TYPES,
            "RETURN_NAMES": cls.RETURN_NAMES,
            "FUNCTION": cls.FUNCTION,
            "CATEGORY": cls.CATEGORY,
        }

        missing_attributes = [
            attr for attr, value in required_attributes.items() if value is None
        ]

        if missing_attributes:
            raise TypeError(
                f"{cls.__name__} class must define the following attributes: "
                f"{', '.join(missing_attributes)}"
            )
