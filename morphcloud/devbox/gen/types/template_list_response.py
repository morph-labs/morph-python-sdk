import typing
import pydantic
from ..core.pydantic_utilities import IS_PYDANTIC_V2, UniversalBaseModel
from .template_summary import TemplateSummary

class TemplateListResponse(UniversalBaseModel):
    object: typing.Optional[str] = None
    data: typing.List[TemplateSummary]
    if IS_PYDANTIC_V2:
        model_config: typing.ClassVar[pydantic.ConfigDict] = pydantic.ConfigDict(extra='allow', frozen=True)
    else:

        class Config:
            frozen = True
            smart_union = True
            extra = pydantic.Extra.allow
