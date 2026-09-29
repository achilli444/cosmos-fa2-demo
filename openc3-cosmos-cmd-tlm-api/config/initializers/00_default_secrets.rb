# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'openc3/utilities/default_secrets'

# Refuse to boot with the public placeholder credentials / no SECRET_KEY_BASE
# unless OPENC3_ALLOW_DEFAULT_PASSWORDS opts in (local demos only). The check
# runs for every environment except test, whose fixtures use the defaults.
unless Rails.env.test?
  OpenC3::DefaultSecrets.check!(service: 'openc3-cosmos-cmd-tlm-api', logger: Rails.logger)
end
