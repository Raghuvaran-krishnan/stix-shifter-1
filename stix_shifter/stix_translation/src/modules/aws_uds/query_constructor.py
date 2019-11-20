from stix_shifter.stix_translation.src.patterns.pattern_objects import ObservationExpression, ComparisonExpression, \
    ComparisonExpressionOperators, ComparisonComparators, Pattern, \
    CombinedComparisonExpression, CombinedObservationExpression, ObservationOperators, StartStopQualifier
from stix_shifter.stix_translation.src.utils.transformers import TimestampToMilliseconds
from stix_shifter.stix_translation.src.json_to_stix import observable
from datetime import datetime, timedelta
import os.path as path
import json
# import logging
import re

# Source and destination reference mapping for ip and mac addresses.
# Change the keys to match the data source fields. The value array indicates the possible data type that can come into from field.
# REFERENCE_DATA_TYPES = {"SourceIpV4": ["ipv4", "ipv4_cidr"],
#                         "SourceIpV6": ["ipv6"],
#                         "DestinationIpV4": ["ipv4", "ipv4_cidr"],
#                         "DestinationIpV6": ["ipv6"]}

# logger = logging.getLogger(__name__)

PROTOCOL_LOOKUP_JSON_FILE = 'json/network_protocol_map.json'
MASTER_CONFIG_FILE = 'json/master_config.json'
START_STOP_PATTERN = r"\d{4}(-\d{2}){2}T\d{2}(:\d{2}){2}(\.\d+)?Z"

class QueryStringPatternTranslator:
    # Change comparator values to match with supported data source operators
    comparator_lookup = {
        ComparisonExpressionOperators.And: "AND",
        ComparisonExpressionOperators.Or: "OR",
        ComparisonComparators.GreaterThan: ">",
        ComparisonComparators.GreaterThanOrEqual: ">=",
        ComparisonComparators.LessThan: "<",
        ComparisonComparators.LessThanOrEqual: "<=",
        ComparisonComparators.Equal: "=",
        ComparisonComparators.NotEqual: "!=",
        ComparisonComparators.Like: "LIKE",
        ComparisonComparators.In: "=",
        ComparisonComparators.Matches: 'LIKE',
        ComparisonComparators.IsSubSet: '',
        # ComparisonComparators.IsSuperSet: '',
        ObservationOperators.Or: 'OR',
        # Treat AND's as OR's -- Unsure how two ObsExps wouldn't cancel each other out.
        ObservationOperators.And: 'OR'
    }

    def __init__(self, pattern: Pattern, data_model_mapper, time_range, from_stix_json_filename):
        self.dmm = data_model_mapper
        self.pattern = pattern
        self._time_range = time_range
        self.json_file = from_stix_json_filename
        self.log_type = self.log_name_extract_from_json(from_stix_json_filename)
        # self._log_config_master_file = self._master_log_file(self.log_type)
        self._log_config_data = self.load_json(MASTER_CONFIG_FILE)
        # self._protocol_lookup_needed = True if self.log_type in ['vpcflow', 'vpcflow1'] else False
        self._protocol_lookup_needed = True if self.log_type in ['vpcflow'] else False
        self._parse_list = []
        self.qualified_queries = []
        self.time_range_lst = []
        self._exclude_non_match_lst = []
        # self._is_single_comp_exp = True
        self._filter_string_exclude = ''
        self._master_query_reference = self._log_config_data.get(self.log_type).get('master_query_reference')
        self.translated = self.parse_expression(pattern)

    @staticmethod
    def log_name_extract_from_json(json_filename):
        """

        :return:
        """
        compiled_regex_json = re.compile('^from_stix_(?P<log_type>.*)_map.json$')
        json_filename_search = compiled_regex_json.search(path.basename(json_filename))
        if json_filename_search:
            return json_filename_search.group('log_type')

    @staticmethod
    def _master_log_file(log_type):
        """
            Function to choose the type of config file to be used for query formation based on log type provided
            as input.
        :param log_type: str, type of log file i.e. guardduty, cloudtrail, VPC flow logs
        :return: str
        """
        master_log_file = None
        if log_type.lower() == 'guardduty':
            master_log_file = path.join('json', 'guardduty_config.json')
        elif log_type.lower() == 'vpcflow':
            master_log_file = path.join('json', 'vpcflow_config.json')
        # elif log_type.lower() == 'vpcflow1':
        #     master_log_file = path.join('json', 'vpcflow_config.json')
        else:
            raise NotImplementedError("Unknown log type for AWS:{}".format(log_type))
        return master_log_file

    def protocol_lookup(self, value):
        """
        Function for protocol number lookup
        :param value:str
        :return:str if log type is vpcflow, list if log type is gaurduty
        """
        protocol_value = []
        value = value.values if hasattr(value, 'values') else value
        protocol_json = self.load_json(PROTOCOL_LOOKUP_JSON_FILE)
        if self._protocol_lookup_needed:
            if isinstance(value, list):
                protocol_value = [protocol_json.get(each_value.lower()) for each_value in value if each_value.lower() in
                                  protocol_json]
            else:
                protocol_value = protocol_json.get(value.lower())
        else:
            if isinstance(value, list):
                # protocol_exist = [each_value for each_value in value if each_value.lower() in protocol_json]
                protocol_value = list(map(str.upper, value))
                existing_protocol_lower = list(map(str.lower, value))
                for index, v in enumerate(existing_protocol_lower):
                    protocol_value.insert(2*index+1, v)
            else:
                protocol_value.extend([value.lower(), value.upper()])
        return protocol_value

    @staticmethod
    def load_json(rel_path_of_file):
        """
        Consumes a json file and returns a dictionary
        :param rel_path_of_file: str, path of json file
        :return: dictionary
        """
        _json_path = path.abspath(path.join(path.join(__file__, ".."), rel_path_of_file))
        if path.exists(_json_path):
            with open(_json_path) as f_obj:
                return json.load(f_obj)
        else:
            raise FileNotFoundError

    @staticmethod
    def _format_set(values) -> str:
        """
        Formatting list of values in the event of IN operation
        :param values: str
        :return: list
        """
        values = values.values if hasattr(values, 'values') else values
        return list(map('"{}"'.format, values))

    @staticmethod
    def _format_matches(value) -> str:
        """
        Formatting value in the event of MATCHES operation
        encapsulating the value inside regex keyword
        :param value: str
        :return: str
        """
        return '/{}/'.format(value) if not isinstance(value, list) else ['/{}/'.format(each) for each in value]

    @staticmethod
    def _format_equality(value) -> str:
        """
        Formatting value in the event of equality operation
        :param value: str
        :return: str
        """
        return '"{}"'.format(value) if not isinstance(value, list) else value

    @staticmethod
    def _format_like(value) -> str:
        """
        Formatting value in the event of LIKE operation
        :param value: str
        :return: str
        """
        # Replacing value with % to .* and _ to . for supporting Like comparator
        if not isinstance(value, list):
            compile_regex = re.compile(r'.*(\%|\_).*')
            if compile_regex.match(value):
                value = '/{}$/'.format(value.replace('%', '.*').replace('_', '.'))
            else:
                value = '"{}"'.format(value)
        return value

    @staticmethod
    def _escape_value(value, comparator=None) -> str:
        if isinstance(value, str):
            return '{}'.format(value.replace('\\', '\\\\').replace('\"', '\\"').replace('(', '\\(').replace(')', '\\)'))
        else:
            return value

    # @staticmethod
    # def _escape_double_quotes(query) -> str:
    #     if isinstance(query, str):
    #         return '{}'.format(query.replace('\"', '\\"'))
    @staticmethod
    def _negate_comparison(comparison_string):
        return "NOT ({})".format(comparison_string)

    # @staticmethod
    # def _check_value_type(value):
    #     value = str(value)
    #     for key, pattern in observable.REGEX.items():
    #         if key != 'date' and bool(re.search(pattern, value)):
    #             return key
    #     return None

    # @staticmethod
    # def _parse_reference(self, stix_field, value_type, mapped_field, value, comparator):
    #     if value_type not in REFERENCE_DATA_TYPES["{}".format(mapped_field)]:
    #         return None
    #     else:
    #         return "{mapped_field} {comparator} {value}".format(
    #             mapped_field=mapped_field, comparator=comparator, value=value)

    # @staticmethod
    def _parse_mapped_fields(self, expression, value, comparator, mapped_fields_array):
        # comparison_string, _exclude_non_match_qry = "", ""
        comparison_string = ""
        mapped_fields_count = len(mapped_fields_array)
        for mapped_field in mapped_fields_array:
            # if mapped_field in self._log_config_data.get('filter_mapping'):
            if expression.comparator == ComparisonComparators.In or isinstance(value, list):
                comparison_string += '({})'.format(' OR '.join(map(lambda x: "{mapped_field} {comparator} "
                                                                             "{value}".
                                                                   format(mapped_field=mapped_field,
                                                                          comparator=comparator,
                                                                          value=x), value)))
            elif expression.comparator == ComparisonComparators.IsSubSet:
                comparison_string += 'isIpv4InSubnet({mapped_field},{value})'.format(mapped_field=mapped_field,
                                                                                     value=value)

                # if expression.comparator == ComparisonComparators.NotEqual or \
                #         expression.comparator == ComparisonComparators.IsSuperSet:
                #     comparator = ':'
                #     comparison_string += "(NOT {mapped_field} {comparator} {value} AND {mapped_field}:*)".format(
                #         mapped_field=mapped_field, comparator=comparator, value=value)
                # elif expression.comparator == ComparisonComparators.GreaterThan or \
                #         expression.comparator == ComparisonComparators.LessThan or \
                #         expression.comparator == ComparisonComparators.GreaterThanOrEqual or \
                #         expression.comparator == ComparisonComparators.LessThanOrEqual:
                #     # Check whether value is in datetime format, Ex: process.created
                #     pattern = "^\d{4}(-\d{2}){2}T\d{2}(:\d{2}){2}(\.\d+)?Z$"
                #     try:
                #         match = bool(re.search(pattern, value))
                #     except:
                #         match = False
                #     if match:
                #         # IF value is in datetime format then do conversion of datetime into
                #         # proper Range query of timestamps supported by elastic_ecs for comparators like :<,:>,:<=,:>=
                #         comparison_string += _get_timestamp(mapped_field, comparator, value)
                #     else:
                #         comparison_string += "{mapped_field}{comparator}{value}".format(mapped_field=mapped_field,
                #                                                                         comparator=comparator,
                #                                                                         value=value)
                # elif expression.comparator == ComparisonComparators.IsSubSet:
                #     comparison_string += "({mapped_field} {comparator} {value} AND {mapped_field}:*)".format(
                #         mapped_field=mapped_field, comparator=comparator, value=value)
            else:
                comparison_string += "{mapped_field} {comparator} {value}".format(mapped_field=
                                                                                  mapped_field,
                                                                                  comparator=comparator,
                                                                                  value=value)
            # Guardduty parsing code starts here
            if 'field_mapping' in self._log_config_data.get(self.log_type):
                field_mapping_from_config = self._log_config_data.get(self.log_type).get('field_mapping').get(
                    mapped_field)
                if isinstance(field_mapping_from_config, dict):
                    parse_value = field_mapping_from_config.get(expression.object_path)
                else:
                    parse_value = field_mapping_from_config
                self._parse_list.append(parse_value)

            self._exclude_non_match_lst.append('strlen({}) > 0'.format(mapped_field))
            # Guardduty parsing code ends here
            # if 'field_mapping' in self._log_config_data.get(self.log_type):
            #     field_mapping_from_config = self._log_config_data.get(self.log_type).get(
            #         mapped_field)
            #     if isinstance(field_mapping_from_config, dict):
            #         parse_value = field_mapping_from_config.get(expression.object_path)
            #     else:
            #         parse_value = field_mapping_from_config
            #     self._parse_list.append(parse_value)

            if mapped_fields_count > 1:
                comparison_string += " OR "
                # _exclude_non_match_qry += " OR "
                mapped_fields_count -= 1
            # else:
            #     raise NotImplementedError(
            #         "{} unsupported for AWS log {}".format(stix_field, path.basename(
            #             self._log_config_master_file).split('_')[0]))
            # self._exclude_non_match_lst.append('strlen({}) > 0'.format(self._log_config_data.get(
            #     'filter_mapping').get(mapped_field)))
        # return comparison_string, _exclude_non_match_qry
        return comparison_string

    # @staticmethod
    def _parse_time_range(self, qualifier, time_range):
        """
        Format the input time range
        i.e <START|STOP>t'2019-04-20T10:43:10.003Z to %d %b %Y %H:%M:%S %z"(i.e 23 Oct 2018 12:20:14 +0000)
        :param qualifier: str | None, input time range i.e START t'2019-04-10T08:43:10.003Z'
        STOP t'2019-04-20T10:43:10.003Z'
        :param stix_obj: str, file or process stix object
        :param relevance_map_dict: dict, relevance property format string
        :param time_range: int, value available from main.py in options variable
        :return: str, format_string bound with time range provided
        """
        format_string = ''
        # format_string_list = []
        # epoch_time_string = "01 Jan 1970 00:00:00 +0000"
        # qualifier_keys_list = ['mapped_field', 'extra_mapped_string', 'transformer', 'default_if_attr_undefined']
        try:
            compile_timestamp_regex = re.compile(START_STOP_PATTERN)
            transformer = TimestampToMilliseconds()
            if qualifier and compile_timestamp_regex.search(qualifier):
                time_range_iterator = map(lambda x: int(transformer.transform(x.group())/1000),
                                          compile_timestamp_regex.finditer(qualifier))
            # Default time range Start time = Now - 5 minutes and Stop time  = Now
            else:
                stop_time = datetime.now()
                start_time = int(round((stop_time - timedelta(minutes=time_range)).timestamp()))
                stop_time = int(round(stop_time.timestamp()))
                # time_range_iterator = map(lambda x: transformer.transform(x),
                #                           [start_time, stop_time])
                time_range_iterator = [start_time, stop_time]
            self.time_range_lst.append([each for each in time_range_iterator])
            return format_string
        except (KeyError, IndexError, TypeError) as e:
            raise e

    @staticmethod
    def _is_reference_value(stix_field):
        return stix_field == 'src_ref.value' or stix_field == 'dst_ref.value'

    @staticmethod
    def _lookup_comparison_operator(self, expression_operator):
        if expression_operator not in self.comparator_lookup:
            raise NotImplementedError("Comparison operator {} unsupported for Dummy adapter".format(expression_operator.name))
        return self.comparator_lookup[expression_operator]

    def _parse_expression(self, expression, qualifier=None) -> str:
        if isinstance(expression, ComparisonExpression):  # Base Case
            # Resolve STIX Object Path to a field in the target Data Model
            stix_object, stix_field = expression.object_path.split(':')
            # Custom condition for protocol lookup if log type == 'vpcflow'
            if stix_field.lower() == 'protocols[*]':
                existing_protocol_value = expression.value
                value = self.protocol_lookup(expression.value)
                if (not value) or (isinstance(value, list) and None in value):
                    raise NotImplementedError("Un-supported protocol '{}' for operation '{}' for aws '{}' logs".format(
                        expression.value, expression.comparator,
                        path.basename(self._log_config_master_file).split('_')[0]))
                expression.value = self._format_set(value) if isinstance(value, list) and not\
                    self._protocol_lookup_needed and expression.comparator not in [ComparisonComparators.Matches,
                                                                                   ComparisonComparators.In]\
                    else value
                # expression.value = value
            # Multiple data source fields may map to the same STIX Object
            mapped_fields_array = self.dmm.map_field_json(stix_object, stix_field, path.basename(self.json_file))
            # Resolve the comparison symbol to use in the query string (usually just ':')
            comparator = self._lookup_comparison_operator(self, expression.comparator)

            # if stix_field == 'start' or stix_field == 'end':
            #     transformer = TimestampToMilliseconds()
            #     expression.value = transformer.transform(expression.value)

            # Some values are formatted differently based on how they're being compared
            if expression.comparator == ComparisonComparators.Matches:  # needs forward slashes
                value = self._format_matches(expression.value)
            # should be (x, y, z, ...)
            elif expression.comparator == ComparisonComparators.In:
                value = self._format_set(expression.value)
            elif expression.comparator == ComparisonComparators.Equal or \
                    expression.comparator == ComparisonComparators.NotEqual:
                # Should be in single-quotes
                value = self._format_equality(expression.value)
            # '%' -> '*' wildcard, '_' -> '?' single wildcard
            elif expression.comparator == ComparisonComparators.Like:
                value = self._format_like(expression.value)
            else:
                # value = self._escape_value(expression.value)
                value = '"{}"'.format(expression.value)

            # comparison_string, _exclude_non_match_qry = self._parse_mapped_fields(expression, value, comparator,
            #                                                                       stix_field, mapped_fields_array)
            comparison_string = self._parse_mapped_fields(expression, value, comparator, mapped_fields_array)
            # Reverting back the protocol value in expression to existing
            if stix_field.lower() == 'protocols[*]':
                expression.value = existing_protocol_value
            if len(mapped_fields_array) > 1:
                # More than one data source field maps to the STIX attribute, so group comparisons together.
                grouped_comparison_string = "(" + comparison_string + ")"
                comparison_string = grouped_comparison_string
                # _exclude_non_match_qry = "(" + _exclude_non_match_qry + ")"

            if expression.negated:
                comparison_string = self._negate_comparison(comparison_string)
            # if qualifier is not None:
            #     return "{} {}".format(comparison_string, qualifier)
            # else:

            # self._exclude_non_match_qry = ' OR '.join(self._exclude_non_match_lst)
            # self._exclude_non_match_lst.append(_exclude_non_match_qry)
            # if self._is_single_comp_exp:
            #     self._filter_string_exclude = ''.join(self._exclude_non_match_lst)
            return "{}".format(comparison_string)

        elif isinstance(expression, CombinedComparisonExpression):
            # self._is_single_comp_exp = False
            operator = self._lookup_comparison_operator(self, expression.operator)
            expression_01 = self._parse_expression(expression.expr1)
            expression_02 = self._parse_expression(expression.expr2)
            if not expression_01:
                query_string = "{}".format(expression_02)
            elif not expression_02:
                query_string = "{}".format(expression_01)
            else:
                query_string = "{} {} {}".format(expression_01, operator, expression_02)
                # self._filter_string_exclude += ' {expr} '.format(expr=' {} '.format(operator).join(
                #         self._exclude_non_match_lst) if len(self._exclude_non_match_lst) > 1 else ' {} {}'.
                #                                                  format(operator,
                #                                                         ''.join(self._exclude_non_match_lst).strip()))
                # self._exclude_non_match_lst = []
            return query_string
            # if not expression_01 or not expression_02:
            #     return ''
            # if isinstance(expression.expr1, CombinedComparisonExpression):
            #     expression_01 = "({})".format(expression_01)
            # if isinstance(expression.expr2, CombinedComparisonExpression):
            #     expression_02 = "({})".format(expression_02)
            # query_string = "{} {} {}".format(expression_01, operator, expression_02)
            # # import pdb;pdb.set_trace()
            # if len(self._exclude_non_match_lst) > 1:
            #     self._filter_string_exclude += ' {expr} '.format(expr=' {} '.format(operator).join(
            #         self._exclude_non_match_lst))
            # else:
            #     self._filter_string_exclude += operator + ' '.join(self._exclude_non_match_lst)
            # self._exclude_non_match_lst = []
            # self._exclude_non_match_qry = ' {operator} '.format(operator=operator.join(self._exclude_non_match_lst))
            # if qualifier is not None:
            #     return "{} {}".format(query_string, qualifier)
            # else:
        elif isinstance(expression, ObservationExpression):
            # return self._parse_expression(expression.comparison_expression, qualifier)
            # self._exclude_non_match_lst = []
            self._filter_string_exclude = ''
            self._parse_list = []
            filter_query = self._parse_expression(expression.comparison_expression, qualifier)
            parse_query = '| '.join(self._parse_list) if self._parse_list else ''
            self._parse_time_range(qualifier, self._time_range)
            self._filter_string_exclude = ' OR '.join(self._exclude_non_match_lst)
            self.qualified_queries.append(self._master_query_reference.format(parse_query=parse_query,
                                                                              fields=', '.join(self._log_config_data
                                                                                               .get(self.log_type)
                                                                                               .get('field_display')),
                                                                              filter_query=filter_query,
                                                                              exclude_non_match=
                                                                              self._filter_string_exclude))
            # self.qualified_queries.append(self._master_query_reference.format(parse_query=parse_query,
            #                                                                   filter_query=filter_query,
            #                                                                   ))
            return None
        # For now not needed - will look at different implementation for qualifier
        # elif hasattr(expression, 'qualifier') and hasattr(expression, 'observation_expression'):
        #     if isinstance(expression.observation_expression, CombinedObservationExpression):
        #         operator = self._lookup_comparison_operator(self, expression.observation_expression.operator)
        #         expression_01 = self._parse_expression(expression.observation_expression.expr1)
        #         # qualifier only needs to be passed into the parse expression once since it will be the same for both expressions
        #         expression_02 = self._parse_expression(expression.observation_expression.expr2, expression.qualifier)
        #         return "{} {} {}".format(expression_01, operator, expression_02)
        #     else:
        #         return self._parse_expression(expression.observation_expression.comparison_expression, expression.qualifier)

        elif isinstance(expression, CombinedObservationExpression):
            self._parse_expression(expression.expr1, qualifier)
            self._parse_expression(expression.expr2, qualifier)
            return None
            # operator = self._lookup_comparison_operator(self, expression.operator)
            # expression_01 = self._parse_expression(expression.expr1)
            # expression_02 = self._parse_expression(expression.expr2)
            # if expression_01 and expression_02:
            #     return "({}) {} ({})".format(expression_01, operator, expression_02)
            # elif expression_01:
            #     return "{}".format(expression_01)
            # elif expression_02:
            #     return "{}".format(expression_02)
            # else:
            #     return ''
        elif isinstance(expression, StartStopQualifier):
            if hasattr(expression, 'observation_expression'):
                return self._parse_expression(getattr(expression, 'observation_expression'), expression.qualifier)
        elif isinstance(expression, Pattern):
            return "{expr}".format(expr=self._parse_expression(expression.expression))
        else:
            raise RuntimeError("Unknown Recursion Case for expression={}, type(expression)={}".format(
                expression, type(expression)))

    def parse_expression(self, pattern: Pattern):
        # for each_json_file in self.dmm.from_stix_files_cnt:
        #     compiled_regex_json = re.compile('^from_stix_(?P<log_type>.*)_map.json$')
        #     json_filename_search = compiled_regex_json.search(path.basename(each_json_file))
        #     if json_filename_search:
        #         self.log_type = json_filename_search.group('log_type')
        #     self._parse_expression(pattern)
        # return None

        return self._parse_expression(pattern)


def translate_pattern(pattern: Pattern, data_model_mapping, options):
    # Query result limit and time range can be passed into the QueryStringPatternTranslator
    # if supported by the data source.
    # result_limit = options['result_limit']
    # Sample output
    # {
    #     "vpc": {
    #         "limit": 0,
    #         "logGroupName": "",
    #         "queryString": "fields @timestamp, @srcAddr, @dstAddr, @srcPort,
    #         @dstPort, @protocol| filter (srcPort = "60" AND (srcAddr = "198.51.100.0" OR dstAddr = "198.51.100.0"))",
    #         "startTime": 1571224113,
    #         "endTime": 1671224169
    #     },
    #     "guardduty": {
    #         "limit": 0,
    #         "logGroupName": "",
    #         "queryString": "fields @timestamp, @message| parse
    #         @message /(?:\"publicIp\"\\:\")(?<srcAddr>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.)
    #         {3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(?:\"\\}\\])/| parse @message /(?:\"ipAddressV4\"\\:\")
    #         (?<dstAddr>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))
    #         (?:\"\\,)/| parse @message /(:?\"protocol\"\\:\")(?<protocol>[a-zA-Z]+)(:?\")/| filter
    #         ((srcAddr = \"12.34.12.1\" OR dstAddr = \"12.34.12.1\") AND (protocol = \"TCP\" OR
    #         protocol = \"tcp\" OR protocol = \"UDP\" OR protocol = \"udp\"))|
    #         filter ((strlen(srcAddr) > 0 OR strlen(dstAddr) > 0) AND strlen(protocol) > 0)",
    #         "startTime": 1571224113,
    #         "endTime": 1671224169
    #     }
    # }

    timerange = options['timerange']
    final_queries = []
    for each_json_file in data_model_mapping.from_stix_files_cnt:
        # translate_query_dict = {}
        queries_obj = QueryStringPatternTranslator(pattern, data_model_mapping, timerange, each_json_file)
        qualifier_list = list(zip(*queries_obj.time_range_lst))
        queries_string = queries_obj.qualified_queries

        # Old code starts here
        # translate_query_dict[queries_obj.log_type] = {}
        # translate_query_dict[queries_obj.log_type]['limit'] = 0
        # translate_query_dict[queries_obj.log_type]['logGroupName'] = ""
        # translate_query_dict[queries_obj.log_type]['queryString'] = queries_string
        # translate_query_dict[queries_obj.log_type]['startTime'] = qualifier_list[0]
        # translate_query_dict[queries_obj.log_type]['endTime'] = qualifier_list[1]
        # Old code ends here

        for index, each_query in enumerate(queries_string, start=0):
            translate_query_dict = dict()
            translate_query_dict['limit'] = 0
            translate_query_dict['logGroupName'] = ""
            translate_query_dict['queryString'] = each_query
            translate_query_dict['startTime'] = qualifier_list[0][index]
            translate_query_dict['endTime'] = qualifier_list[1][index]
            final_queries.append(translate_query_dict)

    # Add space around START STOP qualifiers
    # query = re.sub("START", "START ", query)
    # query = re.sub("STOP", " STOP ", query)

    # Change return statement as required to fit with data source query language.
    # If supported by the language, a limit on the number of results may be desired.
    # A single query string, or an array of query strings may be returned
    # return final_queries, qualifier
    return final_queries
