
from typing import (
    Any,
    Dict,
    TYPE_CHECKING,
    TypeVar,
)

from .base import ConstraintDerived
from .basic import (
    EnsureBool,
    EnsureChoice,
    EnsureFloat,
    EnsureInt,
    EnsureStr,
    EnsureValue,
    NoConstraint,
)
from .compound import (
    EnsureIterableOf,
    EnsureMapping,
)

if TYPE_CHECKING:  # pragma: no cover
    from datalad_next.commands import Parameter

aEnsureParameterConstraint = TypeVar(
    'aEnsureParameterConstraint',
    bound='aEnsureParameterConstraint',
)
aParameter = TypeVar('aParameter', bound='Parameter')


class NoValue:
    """Type to annotate the absence of a value

    For example in a list of parameter defaults. In general `None` cannot
    be used, as it may be an actual value, hence we use a local, private
    type.
    """
    pass


class EnsureParameterConstraint(EnsureMapping):
    """Ensures a mapping from a Python parameter name to a value constraint

    An optional "pass-though" value can be declare that is then exempt from
    validation and is returned as-is. This can be used to support, for example,
    special default values that only indicate the optional nature of a
    parameter. Declaring them as "pass-through" avoids a needless
    complexity-increase of a value constraint that would translate onto
    user-targeted error reporting.
    """
    # valid parameter name for Python and CLI
    # - must start with a lower-case letter
    # - must not contain symbols other than lower-case letters,
    #   digits, and underscore
    valid_param_name_regex = r'[a-z]{1}[a-z0-9_]*'

    def __init__(self,
                 constraint: ConstraintDerived,
                 passthrough: Any = NoValue):
        """
        Parameters
        ----------
        constraint:
          Any ``Constraint`` subclass instance that will be used to validate
          parameter values.
        passthrough:
          A value that will not be subjected to validation by the value
          constraint, but is returned as-is. This can be used to exempt
          default values from validation, e.g. when defaults are only
          placeholder values to indicate the optional nature of a parameter.
        """
        super().__init__(
            key=EnsureStr(
                match=EnsureParameterConstraint.valid_param_name_regex),
            value=constraint,
            # make it look like dict(...)
            delimiter='=',
        )
        self._passthrough = passthrough

    @property
    def parameter_constraint(self):
        return self._value_constraint

    @property
    def passthrough_value(self):
        return self._passthrough

    def __call__(self, value) -> Dict:
        key, val = self._get_key_value(value)
        key = self._key_constraint(key)
        val = self._value_constraint(val) \
            if val != self.passthrough_value else val
        return {key: val}

    @classmethod
    def from_parameter(
            cls,
            spec: aParameter,
            default: Any,
            item_constraint: ConstraintDerived = None,
            nargs: str or int = None) -> aEnsureParameterConstraint:
        """
        Parameters
        ----------
        spec: Parameter
          Instance of a datalad-core Parameter. If not overwritten by values
          given to the other arguments of this method, item constraints,
          number of arguments and other argparse-specific information
          is taken from this object and processed to built a comprehensive
          constraint that handles all aspects of the specification in a
          homogenous fashion via the Constraint interface.
        default: Any
          A parameter's default value. Any (intermediate) constraint is tested
          whether it considers the default to be a valid value. If not,
          the constraint is automatically expanded to also cover this
          particular value.
        item_constraint:
          If given, it override any constraint declared in the Parameter
          instance given to `spec`
        nargs:
          If given, it override any nargs setting declared in the Parameter
          instance given to `spec`.
        """
        value_constraint = _get_comprehensive_constraint(
            spec,
            default,
            item_constraint,
            nargs,
        )
        return cls(value_constraint)


# that mapping is NOT to be expanded!
# it is a legacy leftover. It's usage triggers a DeprecationWarning
_constraint_spec_map = {
    'float': EnsureFloat(),
    'int': EnsureInt(),
    'bool': EnsureBool(),
    'str': EnsureStr(),
}


def _get_comprehensive_constraint(
        param_spec: aParameter,
        default: Any,
        item_constraint_override: ConstraintDerived = None,
        nargs_override: str or int = None):
    action = param_spec.cmd_kwargs.get('action')
    # definitive per-item constraint, consider override
    # otherwise fall back on Parameter.constraints
    constraint = item_constraint_override or param_spec.constraints

    if not (constraint is None or hasattr(constraint, '__call__')):
        import warnings
        warnings.warn("Literal constraint labels are no longer supported.",
                      DeprecationWarning)
        try:
            return _constraint_spec_map[constraint]
        except KeyError:
            raise ValueError(
                f"unsupported constraint specification '{constraint}'")

    if not constraint:
        if action in ('store_true', 'store_false'):
            constraint = EnsureBool()
        elif param_spec.cmd_kwargs.get('choices'):
            constraint = EnsureChoice(*param_spec.cmd_kwargs.get('choices'))
        else:
            # always have one for simplicity
            constraint = NoConstraint()

    # we must addtionally consider the following nargs spec for
    # a complete constraint specification
    # (int, '*', '+'), plus action=
    # - 'store_const' TODO
    # - 'store_true' and 'store_false' TODO
    # - 'append'
    # - 'append_const' TODO
    # - 'count' TODO
    # - 'extend' TODO

    # get the definitive argparse "nargs" value
    nargs = nargs_override or param_spec.cmd_kwargs.get('nargs', None)
    # try making a specific number explicit via dtype change
    try:
        nargs = int(nargs)
    except (ValueError, TypeError):
        pass

    # TODO reconsider using `list`, with no length-check it could
    # be a generator
    if isinstance(nargs, int):
        # we currently consider nargs=1 to be a request of a
        # single item, not a forced single-item list
        if nargs > 1:
            # sequence of a particular length
            constraint = EnsureIterableOf(
                list, constraint, min_len=nargs, max_len=nargs)
    elif nargs == '*':
        # datalad expects things often/always to also work for a single item
        constraint = EnsureIterableOf(list, constraint) | constraint
    elif nargs == '+':
        # sequence of at least 1 item, always a sequence,
        # but again datalad expects things often/always to also work for
        # a single item
        constraint = EnsureIterableOf(
            list, constraint, min_len=1) | constraint
    # handling of `default` and `const` would be here
    #elif nargs == '?'

    if action == 'append':
        # wrap into a(nother) sequence
        # (think: list of 2-tuples, etc.
        constraint = EnsureIterableOf(list, constraint)

    # lastly try to validate the default, if that fails
    # wrap into alternative
    try:
        constraint(default)
    except Exception:
        constraint = constraint | EnsureValue(default)

    return constraint
